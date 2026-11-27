// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func verdictEvidenceFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newVerdictEvidenceSender(t *testing.T, f *roleExplanationAPIFixture, correlator ...*incident.Correlator) func(string, string) *agent.EvidenceClient {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl-verdict-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := verdictEvidenceFile(t, dir, "ca.crt", ca.CertPEM())
	server, err := agenttransport.New(verdictEvidenceFile(t, dir, "server.crt", cert), verdictEvidenceFile(t, dir, "server.key", key), caFile, f.pool, bus.NewMemory(), nil, f.server.log)
	if err != nil {
		t.Fatal(err)
	}
	server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	if len(correlator) > 0 {
		server.WithFaultCorrelator(correlator[0])
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(ctx, listener) }()
	t.Cleanup(func() { stop(); <-done })
	return func(tenant, sender string) *agent.EvidenceClient {
		t.Helper()
		identity := crypto.EntitySPIFFEID(tenant, sender)
		cert, key, err := ca.IssueClientCert(sender, identity, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(cert)
		if block == nil {
			t.Fatal("issued evidence certificate missing")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, sender, identity, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
			t.Fatal(err)
		}
		client, err := agent.DialEntityEvidence(listener.Addr().String(), verdictEvidenceFile(t, dir, tenant+"-"+sender+".crt", cert), verdictEvidenceFile(t, dir, tenant+"-"+sender+".key", key), caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
}

func seedVerdictRealHTTPTest(t *testing.T, f *roleExplanationAPIFixture, tenant, sender, target, caFile string) testspec.ExecutableDefinition {
	t.Helper()
	definition := testspec.ExecutableDefinition{ID: gouuid.NewString(), Type: "http", Target: target, IntervalSeconds: 30, TimeoutSeconds: 5,
		Params: map[string]string{"allow_private_targets": "true", "ca_file": caFile, "expect_status": "200"}}
	params, err := json.Marshal(definition.Params)
	if err != nil {
		t.Fatal(err)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Agents{}).Register(ctx, sc, sender, "verdict HTTPS "+sender, "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, sender), nil); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'actual HTTPS verdict '||$2::uuid::text,'http',$3,30,5,$4::jsonb,true)`, tenant, definition.ID, target, params); err != nil {
			return err
		}
		registry := store.NewEntityRegistry(f.pool)
		if err := registry.AssignPathTestContext(ctx, sc, definition.ID, f.contextID); err != nil {
			return err
		}
		return registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: sender, Kind: entity.PathAgent, SourceRef: definition.ID}, f.contextID, f.routerID)
	})
	return definition
}

type verdictHTTPSLab struct {
	url         string
	certificate []byte
	collect     func(context.Context, int, testspec.ExecutableDefinition) (canary.Result, error)
}

func TestIncidentVerdictRealHTTPSMTLSAndSignedReadersKeepTenantIsolation(t *testing.T) {
	proveIncidentVerdictRealHTTPS(t, "", func(t *testing.T, code int) verdictHTTPSLab {
		target := httptest.NewTLSServer(overlappingVerdictHTTPHandler(code, nil))
		t.Cleanup(target.Close)
		return verdictHTTPSLab{
			url:         target.URL,
			certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}),
			collect: func(ctx context.Context, _ int, definition testspec.ExecutableDefinition) (canary.Result, error) {
				return collectVerdictHTTP(ctx, definition)
			},
		}
	})
}

func proveIncidentVerdictRealHTTPS(t *testing.T, provider string, startLab func(*testing.T, int) verdictHTTPSLab) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	if provider != "" {
		f.server.WithOpenDataStatus(verdictPublishedRanges(t, time.Now().UTC().Add(-time.Minute), time.Hour), nil, nil)
	}
	seedInterfaceRoleMCPConsent(f)
	sender := newVerdictEvidenceSender(t, f)
	dir := t.TempDir()
	canary.SetCAFileDir(dir)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	var incidents [2]string
	var windows [2]incident.VerdictInput
	for lane, tenant := range f.tenants {
		code := http.StatusServiceUnavailable
		if lane == 1 {
			code = http.StatusOK
		}
		lab := startLab(t, code)
		caFile := verdictEvidenceFile(t, dir, tenant+".crt", lab.certificate)
		id := gouuid.NewString()
		incidents[lane] = id
		var actor *auth.Principal
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'actual HTTPS fault',$3,$4,true)`, tenant, id, f.contextID, f.routerID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		definitions := make([]testspec.ExecutableDefinition, 2)
		agents := []string{gouuid.NewString(), gouuid.NewString()}
		clients := make([]*agent.EvidenceClient, 2)
		for i := range definitions {
			definitions[i] = seedVerdictRealHTTPTest(t, f, tenant, agents[i], lab.url+"/health", caFile)
			clients[i] = sender(tenant, agents[i])
		}
		results := runVerdictHTTPPair(t, definitions, lab.collect)
		from, to := results[0].StartedAt, results[0].StartedAt.Add(results[0].Duration)
		for _, result := range results {
			if result.StartedAt.Before(from) {
				from = result.StartedAt
			}
			if completed := result.StartedAt.Add(result.Duration); completed.After(to) {
				to = completed
			}
		}
		input := incident.VerdictInput{From: from.Truncate(time.Microsecond), To: to.Add(time.Microsecond)}
		windows[lane] = input
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for i, result := range results {
			if result.Success != (code == http.StatusOK) || result.HTTP == nil || result.HTTP.StatusCode != code || !result.HTTP.TLSVerified || !result.HTTP.SameOrigin {
				t.Fatal("actual primary HTTPS response facts changed", result.Success, result.HTTP)
			}
			digest, err := testspec.DefinitionHash(definitions[i])
			if err != nil {
				t.Fatal(err)
			}
			completed := result.StartedAt.Add(result.Duration)
			response := &entity.ProbeHTTPResponse{StatusCode: result.HTTP.StatusCode, TLSVerified: result.HTTP.TLSVerified, SameOrigin: result.HTTP.SameOrigin}
			if provider != "" {
				peer := result.HTTP.PeerAddress
				if !peer.IsGlobalUnicast() || peer.IsPrivate() {
					t.Fatal("routed HTTPS response did not retain its socket peer", peer)
				}
				response.PeerAddress = peer.String()
			}
			claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agents[i], Kind: entity.PathAgent, SourceRef: definitions[i].ID}, Alias: entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: definitions[i].ID}, SourceRef: "probe:configured-test", ObservedAt: completed,
				Outcome: &entity.ProbeOutcome{Version: 2, DefinitionHash: digest, CanaryType: "http", StartedAt: result.StartedAt, CompletedAt: completed, Success: result.Success, HTTPResponse: response}}
			if accepted, unresolved, err := clients[i].Submit(t.Context(), []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("actual mTLS HTTP evidence was not retained", accepted, unresolved, err)
			}
			if lane == 0 && i == 0 {
				thin, err := f.server.computeIncidentVerdict(ctx, actor, id, input.From, input.To, 128<<20)
				if err != nil || thin.Domain != incident.FaultUnknown || thin.RemoteProvider != nil ||
					len(thin.Hypotheses) != 4 || len(thin.Hypotheses[3].For) != 1 {
					t.Fatal("a single verified failure must be cited without attributing the incident", thin.Domain, err)
				}
			}
		}
		got, err := f.server.computeIncidentVerdict(ctx, actor, id, input.From, input.To, 128<<20)
		want := incident.FaultRemoteService
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want {
			t.Fatal("actual HTTPS/mTLS original join selected the wrong tenant/domain", got.Domain, want, err)
		}
		if provider != "" && lane == 0 {
			if got.RemoteProvider == nil || got.RemoteProvider.Provider != provider || got.RemoteProvider.Service != "S3" ||
				len(got.RemoteProvider.Sources) != 1 || len(got.Hypotheses[3].For) != 2 {
				t.Fatal("two routed HTTPS failures lost their published provider provenance", got.RemoteProvider)
			}
		} else if got.RemoteProvider != nil {
			t.Fatal("healthy or unattributable probes acquired provider provenance")
		}
		proveIncidentVerdictServedReaders(t, f, tenant, id, input, got)
		proveIncidentVerdictSignedExport(t, f, tenant, id, input, got)
	}
	for lane, tenant := range f.tenants {
		proveIncidentVerdictForeignReaderRefusal(t, f, tenant, incidents[1-lane], windows[1-lane])
	}
}

func overlappingVerdictHTTPHandler(code int, accept func(*http.Request) bool) http.Handler {
	release := make(chan struct{})
	var arrived atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if accept != nil && !accept(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if arrived.Add(1) == 2 {
			close(release)
		}
		select {
		case <-release:
			w.WriteHeader(code)
		case <-r.Context().Done():
		}
	})
}

func collectVerdictHTTP(ctx context.Context, definition testspec.ExecutableDefinition) (canary.Result, error) {
	probe, err := canary.NewHTTP(canary.Config{Type: "http", Target: definition.Target, Timeout: 5 * time.Second, Params: definition.Params})
	if err != nil {
		return canary.Result{}, err
	}
	return probe.Run(ctx)
}

func runVerdictHTTPPair(t *testing.T, definitions []testspec.ExecutableDefinition, collect func(context.Context, int, testspec.ExecutableDefinition) (canary.Result, error)) []canary.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type completed struct {
		index  int
		result canary.Result
		err    error
	}
	finished := make(chan completed, len(definitions))
	for i, definition := range definitions {
		go func() {
			result, err := collect(ctx, i, definition)
			finished <- completed{i, result, err}
		}()
	}
	results := make([]canary.Result, len(definitions))
	for range results {
		select {
		case item := <-finished:
			if item.err != nil {
				t.Fatal("actual HTTP collector failed", item.err)
			}
			results[item.index] = item.result
		case <-ctx.Done():
			t.Fatal("the two actual HTTPS requests did not complete", ctx.Err())
		}
	}
	return results
}
