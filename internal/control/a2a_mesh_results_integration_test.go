// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/version"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestA2AMeshSignedLoopbackResultsAndTenantIsolation(t *testing.T) {
	fixture, db := setupAPIServerWithLatest(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	pool := db.Pool()
	a, b := freshTenant(t, db, "mesh-healthy"), freshTenant(t, db, "mesh-loss")
	in := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}

	broker := a2a.NewBroker()
	srv := New(&config.Config{AuthMode: "session"}, fixture.log, db, pool, nil, nil).
		WithTenantStatus(NewTenantStatusCache(pool, 0)).WithA2ABroker(broker)
	api := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(api.Close)
	operator := func(tenant string, permissions ...string) (*sdk.Client, string) {
		t.Helper()
		var userID string
		in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, uuid(t)+"@mesh.invalid", "Mesh operator")
			if err != nil {
				return err
			}
			userID = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, uuid(t), "Mesh operator", "Mesh integration")
			if err != nil {
				return err
			}
			for _, permission := range permissions {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID)
		})
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(pool).CreateWithLifetime(ctx, tenant, userID, "mesh", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		return sdk.NewClient(api.URL, sdk.WithHTTPClient(api.Client()), sdk.WithToken(token)), userID
	}
	opA, userA := operator(a, "agent.read", "agent.write", "topology.read")
	opB, userB := operator(b, "agent.read", "agent.write", "topology.read")

	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl-mesh-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := verdictEvidenceFile(t, dir, "ca.crt", ca.CertPEM())
	server, err := agenttransport.New(verdictEvidenceFile(t, dir, "server.crt", cert), verdictEvidenceFile(t, dir, "server.key", key),
		caFile, pool, bus.NewMemory(), broker, fixture.log)
	if err != nil {
		t.Fatal(err)
	}
	server.WithA2AMeshResults(srv.A2AMeshScheduler(), A2AMeshSignalWriter(time.Minute, fixture.log, nil))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(ctx, listener) }()
	t.Cleanup(func() { cancel(); <-done })

	// Both tenants use real issued certificates and TLS registration. The
	// unissued certificate has a valid chain and the same SPIFFE ID as a
	// registered agent and must leave its responder assignment untouched.
	issue := func(tenant, id string, registered bool) (*agent.Client, agent.TLSConfig) {
		t.Helper()
		identity := crypto.AgentSPIFFEID(tenant, id)
		cert, key, err := ca.IssueClientCert(id, identity, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if registered {
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("test agent certificate is missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant, id, identity, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		suffix := uuid(t)
		tls := agent.TLSConfig{CAFile: caFile, ServerName: "localhost",
			CertFile: verdictEvidenceFile(t, dir, suffix+".crt", cert), KeyFile: verdictEvidenceFile(t, dir, suffix+".key", key)}
		client, err := agent.Dial(listener.Addr().String(), tls.CertFile, tls.KeyFile, tls.CAFile, tls.ServerName)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if registered {
			if _, err := client.Register(ctx, &agentv1.RegisterRequest{Hostname: id, AgentVersion: version.Get().Version, Capabilities: []string{"a2a"}}); err != nil {
				t.Fatal(err)
			}
		}
		return client, tls
	}
	eastA, westA, eastB, westB := uuid(t), uuid(t), uuid(t), uuid(t)
	clientA, tlsEast := issue(a, eastA, true)
	_, tlsWest := issue(a, westA, true)
	initB, _ := issue(b, eastB, true)
	respB, _ := issue(b, westB, true)
	unissued, _ := issue(a, eastA, false)
	start := func(httpClient *sdk.Client, east, west, westSite string) []byte {
		t.Helper()
		body := map[string]any{"mode": "udp", "count": 3, "agents": []a2a.SiteAgent{
			{AgentID: east, Site: "east"}, {AgentID: west, Site: westSite},
		}}
		mesh, err := httpClient.StartA2aMesh(ctx, sdk.StartA2aMeshRequest{Body: &body})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(mesh)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	const firstSite, secondSite = "Blue private west mesh", "Red private west mesh"
	start(opA, eastA, westA, firstSite)
	startedB := start(opB, eastB, westB, secondSite)
	if task, err := unissued.PollCoordination(ctx); status.Code(err) != codes.Unauthenticated || task.GetHasTask() {
		t.Fatal("unissued credential received a task", err)
	}

	for id, tls := range map[string]agent.TLSConfig{eastA: tlsEast, westA: tlsWest} {
		cfg := &agent.Config{
			ControlPlane: agent.ControlPlaneConfig{GRPCAddr: listener.Addr().String()}, TLS: tls,
			Agent: agent.Meta{Hostname: id, Capabilities: []string{"a2a"}},
			A2A: agent.A2AConfig{Enabled: true, AdvertiseHost: "127.0.0.1", AllowPrivateTargets: true,
				PollInterval: agent.Duration(40 * time.Millisecond), ResponderTTL: agent.Duration(8 * time.Second)},
			Buffer: agent.BufferConfig{Dir: filepath.Join(dir, id), MaxRecords: 32},
		}
		runtime, err := agent.New(cfg, canary.NewRegistry(), fixture.log)
		if err != nil {
			t.Fatal(err)
		}
		runCtx, stop := context.WithCancel(ctx)
		exited := make(chan error, 1)
		go func() { exited <- runtime.Run(runCtx) }()
		t.Cleanup(func() {
			stop()
			if err := <-exited; err != nil {
				t.Error(err)
			}
		})
	}

	// B measures its own loopback endpoint. The test holds a bound UDP socket
	// and deliberately withholds echoes, then checks receipt of all 3 probes.
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	responder, err := respB.PollCoordination(ctx)
	if err != nil || responder.GetTask().GetRole() != agentv1.A2ARole_A2A_ROLE_RESPONDER {
		t.Fatal("missing B responder assignment", err)
	}
	probeSession := responder.GetTask().GetSessionId()
	sessionID := a2a.MeshSessionHandle(probeSession)
	if sessionID == "" || !bytes.Contains(startedB, []byte(sessionID)) || bytes.Contains(startedB, []byte(probeSession)) {
		t.Fatal("mesh start did not publish only the public session handle")
	}
	port := sink.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	if err := respB.ReportEndpoint(ctx, probeSession, "127.0.0.1", uint32(port)); err != nil {
		t.Fatal(err)
	}
	var task *agentv1.A2ATask
	for range 2 {
		next, err := initB.PollCoordination(ctx)
		if err != nil || !next.GetHasTask() {
			t.Fatal("missing B assignment", err)
		}
		if next.GetTask().GetSessionId() == probeSession {
			task = next.GetTask()
			break
		}
	}
	if task.GetRole() != agentv1.A2ARole_A2A_ROLE_INITIATOR || len(task.GetMeshResultKey()) != a2a.MeshResultKeyBytes {
		t.Fatal("missing B initiator signing assignment")
	}
	measured, err := canary.RunA2AInitiator(ctx, "udp", sink.LocalAddr().String(), int(task.GetCount()),
		300*time.Millisecond, westB, probeSession, canary.NewTargetGuard(true))
	if err != nil || measured.Success || measured.Metrics["loss.ratio"] != 1 {
		t.Fatal("controlled no-echo path did not measure full loss", measured, err)
	}
	if err := sink.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	for range 3 {
		if n, _, err := sink.ReadFromUDP(buf); err != nil || n == 0 {
			t.Fatal("controlled socket did not receive the measured probe", n, err)
		}
	}

	wire := &resultv1.Result{TenantId: b, AgentId: eastB, CanaryType: measured.Type, ServerAddress: measured.Target,
		Success: measured.Success, ErrorMessage: measured.Error, StartTimeUnixNano: measured.StartedAt.UnixNano(),
		DurationNano: int64(measured.Duration), Attributes: measured.Attributes, Metrics: measured.Metrics, ResultId: uuid(t)}
	sign := func() *agentv1.StreamResultsRequest {
		t.Helper()
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.StreamResultsRequest{Payload: payload, A2AMeshProof: &agentv1.A2AMeshResultProof{
			SessionId: sessionID, Mac: a2a.SignMeshResult(task.GetMeshResultKey(), sessionID, payload),
		}}
	}
	send := func(client *agent.Client, frames ...*agentv1.StreamResultsRequest) {
		t.Helper()
		stream, err := client.StreamResults(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			if err := stream.Send(frame); err != nil {
				t.Fatal(err)
			}
		}
		ack, err := stream.CloseAndRecv()
		if err != nil || ack.GetAccepted() != uint64(len(frames)) {
			t.Fatal("unexpected stream disposition", ack, err)
		}
	}
	original := sign()
	send(clientA, original)
	tampered := proto.CloneOf(original)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	send(initB, tampered)
	in(b, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, "SELECT count(*) FROM a2a_mesh_results").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("invalid frame retained %d results", count)
		}
		return nil
	})

	wire.ResultId = uuid(t)
	send(initB, original, original, sign())
	loss, err := opB.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{SessionId: &sessionID})
	if err != nil || len(loss.Topology) != 1 || loss.Topology[0].Status != "degraded" ||
		loss.Topology[0].SessionId != sessionID || loss.Topology[0].Metrics["loss.ratio"] != 1 || loss.Topology[0].ObservedAt == "" {
		t.Fatal("owned signed loss missing from topology", loss, err)
	}
	if private, err := opB.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{SessionId: &probeSession}); err != nil || len(private.Topology) != 0 {
		t.Fatal("topology resolved the private probe credential", err)
	}
	if foreign, err := opA.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{SessionId: &sessionID}); err != nil || len(foreign.Topology) != 0 {
		t.Fatal("A could read B's site edge", foreign, err)
	}
	readerWithoutAgents, _ := operator(b, "events.read")
	var forbidden *sdk.SDKError
	if _, err := readerWithoutAgents.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{SessionId: &sessionID}); !errors.As(err, &forbidden) || forbidden.StatusCode != http.StatusForbidden {
		t.Fatal("tenant reader without agent.read could read the site edge", err)
	}
	measurementsDue := time.NewTimer(25 * time.Second)
	defer measurementsDue.Stop()
	for {
		healthy, err := opA.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if len(healthy.Topology) == 2 && healthy.Topology[0].Status == "healthy" && healthy.Topology[1].Status == "healthy" {
			break
		}
		select {
		case <-measurementsDue.C:
			t.Fatal("coordinators never produced two healthy site edges", healthy)
		case <-time.After(250 * time.Millisecond):
		}
	}
	// Read both isolated results through the shipped Topology page, using the
	// same HTTPS API and exact issued mTLS measurements as the SDK assertions.
	webCA := verdictEvidenceFile(t, dir, "web-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}))
	readCLI := func(client *sdk.Client) []sdk.A2AMeshEdge {
		t.Helper()
		var stdout, stderr bytes.Buffer
		env := map[string]string{"PROBECTL_API_URL": api.URL, "PROBECTL_API_TOKEN": client.Token, "PROBECTL_CA_FILE": webCA}
		args := []string{"a2a", "mesh-status", "--query", "session_id=" + sessionID, "--json"}
		if rc := cli.RunWithStdin(args, func(key string) string { return env[key] }, bytes.NewReader(nil), &stdout, &stderr); rc != 0 {
			t.Fatalf("mesh-status exited %d: %s", rc, stderr.String())
		}
		var topology sdk.A2AMeshTopology
		if err := json.Unmarshal(stdout.Bytes(), &topology); err != nil {
			t.Fatal(err)
		}
		return topology.Topology
	}
	if owned, foreign := readCLI(opB), readCLI(opA); len(owned) != 1 || owned[0].SessionId != sessionID || owned[0].Status != "degraded" || len(foreign) != 0 {
		t.Fatal("mesh-status did not preserve the tenant's session lookup", owned, foreign)
	}
	for _, lane := range []struct{ tenant, user, own, foreign, status, theme string }{
		{a, userA, firstSite, secondSite, "Healthy", "light"},
		{b, userB, secondSite, firstSite, "Degraded", "dark"},
	} {
		t.Run("topology/"+lane.theme, func(t *testing.T) {
			var grants []auth.PermissionGrant
			in(lane.tenant, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", lane.user)
				return err
			})
			cookie, err := srv.sessions.Issue(t.Context(), auth.Session{TenantID: lane.tenant, UserID: lane.user,
				Email: "mesh@local.invalid", DisplayName: "Mesh operator", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
			if err != nil {
				t.Fatal(err)
			}
			const table = `table:has(caption:text-is("Current directed site mesh edges"))`
			testsupport.RenderUI(t, testsupport.RenderSpec{
				URL: api.URL + "/ui/topology", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
				TrustCertFiles: []string{webCA}, CAFile: webCA, Theme: lane.theme, Accessibility: true, TimeoutMs: 20000,
				Expect: []string{"Site mesh measurements", lane.own}, Absent: []string{lane.foreign},
				Steps:    []testsupport.RenderStep{{Click: "Refresh site mesh", ExpectWithin: table, Expect: []string{lane.own, lane.status}, Absent: []string{lane.foreign}}},
				Controls: []testsupport.RenderControl{{Role: "table", Name: "Current directed site mesh edges"}},
			})
		})
	}
	in(b, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Agents{}).Delete(ctx, sc, eastB)
	})
	if _, err := initB.Register(ctx, &agentv1.RegisterRequest{Hostname: eastB, AgentVersion: version.Get().Version, Capabilities: []string{"a2a"}}); err != nil {
		t.Fatal(err)
	}
	if replaced, err := opB.GetA2aMesh(ctx, sdk.GetA2aMeshRequest{SessionId: &sessionID}); err != nil || len(replaced.Topology) != 0 {
		t.Fatal("recreated agent inherited the prior registration's edge", replaced, err)
	}

	for tenant, want := range map[string]int{a: 4, b: 1} {
		in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var owned, foreign, signals int
			// No tenant WHERE predicate on the base counts. The app role's
			// FORCE RLS must still hide the other tenant's originals and signal.
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE tenant_id<>$1)
 FROM a2a_mesh_results`, tenant).Scan(&owned, &foreign); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE kind='a2a.mesh.degraded'`).Scan(&signals); err != nil {
				return err
			}
			if owned != want || foreign != 0 || (tenant == a && signals != 0) || (tenant == b && signals != 1) {
				return fmt.Errorf("tenant %s stored %d originals, %d foreign originals and %d signals", tenant, owned, foreign, signals)
			}
			if tenant != b {
				return nil
			}
			var digest []byte
			var started int64
			if err := sc.Q.QueryRow(ctx, `SELECT payload_sha256,started_unix_nano FROM a2a_mesh_results`).Scan(&digest, &started); err != nil {
				return err
			}
			if !bytes.Equal(digest, crypto.Hash(original.Payload)) || started != measured.StartedAt.UnixNano() {
				return fmt.Errorf("stored loss did not preserve the signed original")
			}
			return nil
		})
	}
}
