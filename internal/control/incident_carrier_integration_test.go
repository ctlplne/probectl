// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Original source observations are modeled; TLS, issued evidence identities,
// current application-role Postgres/RLS, signing and served SDK reads are real.
func TestCarrierExportKeepsCompleteOriginalsOfflineAndCurrentTenantAuthority(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private)
	ids := map[string]string{}
	windows := map[string]incident.CarrierInput{}
	agents := map[string][]string{}
	sender := newVerdictEvidenceSender(t, f)
	for lane, tenant := range f.tenants {
		ids[tenant] = gouuid.NewString()
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permAIQuery, permChangeRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,prefix,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'PRIVATE CUSTOMER password=carrier-fixture-only','198.19.0.0/24',$3,$4,true)`, tenant, ids[tenant], f.contextID, f.routerID); err != nil {
				return err
			}
			_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRoleTransit)
			return err
		})
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		// Both independently authenticated ICMP sources belong to this incident's
		// router. Neither changes the actual control-plane trace vantage.
		for range 2 {
			agent := gouuid.NewString()
			agents[tenant] = append(agents[tenant], agent)
			definition := seedVerdictCarrierTest(t, f, tenant, agent, "198.51.100.10")
			digest, err := testspec.DefinitionHash(definition)
			if err != nil {
				t.Fatal(err)
			}
			client := sender(tenant, agent)
			at := f.observedAt(tenant)
			measurement := &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at.Add(time.Microsecond), Requested: 3, Attempted: 3, Transmitted: 3, Replies: uint32(lane + 1), Responders: []string{definition.Target}, ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{100}, ExecutionNanos: 1000}}
			if lane == 1 {
				measurement.RoundTrips.Nanos = append(measurement.RoundTrips.Nanos, 300)
			}
			claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: measurement.CompletedAt, ICMP: measurement}
			if n, unresolved, err := client.Submit(t.Context(), []entity.Observation{claim}); err != nil || n != 1 || unresolved != 0 {
				t.Fatal("original carrier outcome refused", n, unresolved, err)
			}
		}
		traceStart := f.observedAt(tenant)
		traceEnd := f.observedAt(tenant)
		traceContext := pathstore.WithDiscoveryCompletedAt(pathstore.WithDiscoveryStartedAt(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), traceStart), traceEnd)
		if err := f.server.pathStore.Save(traceContext, tenant, &path.Path{Target: "198.51.100.10", TargetIP: "198.51.100.10", Vantage: path.VantageControlPlane, Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "10.42.0.2", Sent: 3, Received: 2, Geo: &path.HopGeo{City: "PRIVATE CUSTOMER", Source: "password=carrier-fixture-only"}}}}}}); err != nil {
			t.Fatal(err)
		}
		from, err := time.Parse(time.RFC3339Nano, proof.windows[tenant].Get("health_from"))
		if err != nil {
			t.Fatal(err)
		}
		windows[tenant] = incident.CarrierInput{From: from, To: f.observedAt(tenant)}
	}
	for _, window := range windows {
		if delay := time.Until(window.To); delay > 0 {
			if delay > 5*time.Second {
				t.Fatal("fixture database clock exceeds existing skew allowance")
			}
			time.Sleep(delay)
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	fetch := func(tenant, id string) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(incidentEvidenceExportInput{Carrier: func() *incident.CarrierInput { v := windows[tenant]; return &v }()})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/exports", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	for lane, tenant := range f.tenants {
		code, raw := fetch(tenant, ids[tenant])
		if code != http.StatusOK {
			t.Fatal("carrier export unavailable", code, string(raw))
		}
		manifest, err := evidence.Verify(raw)
		if err != nil || manifest.Profile != "carrier" || !manifest.Window.From.Equal(windows[tenant].From) || !manifest.Window.To.Equal(windows[tenant].To) {
			t.Fatal("carrier profile/window or offline verification changed", err)
		}
		if bytes.Contains(raw, []byte(tenant)) || bytes.Contains(raw, []byte("PRIVATE CUSTOMER")) || bytes.Contains(raw, []byte("carrier-fixture-only")) {
			t.Fatal("carrier package disclosed unrelated customer/tenant prose")
		}
		var pkg evidence.Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatal(err)
		}
		if len(pkg.Attachments) != 1 {
			t.Fatal("carrier profile mixed unrelated exports")
		}
		var pack incident.CarrierPack
		if err := json.Unmarshal(pkg.Attachments[0].Content, &pack); err != nil {
			t.Fatal(err)
		}
		if len(pack.Vantages) != 2 || len(pack.Routing) != 1 || pack.Routing[0].Routing == nil || len(pack.Handoffs) != 1 || len(pack.Handoffs[0].Counters) != 2*len(pathHealthMetricNames) {
			t.Fatal("complete original carrier sources omitted", len(pack.Vantages), len(pack.Routing), len(pack.Handoffs), pack.Coverage)
		}
		for _, v := range pack.Vantages {
			if len(v.Traces) != 1 || v.Traces[0].Vantage != path.VantageControlPlane || v.Traces[0].Path.Hops[0].Nodes[0].Geo != nil {
				t.Fatal("carrier trace lost its source vantage or exposed private location metadata")
			}
			if v.Measurements.Packets == nil || v.Measurements.Packets.Replies != []string{"1", "2"}[lane] || v.Measurements.Latency == nil || v.Measurements.Latency.MeanNanos != []string{"100", "200"}[lane] || v.Measurements.Observations[0].EvidenceID == "" {
				t.Fatal("carrier original packet/RTT population changed")
			}
		}
		exact := false
		for _, counter := range pack.Handoffs[0].Counters {
			if counter.Value == "9007199254740993" {
				exact = true
			}
		}
		if !exact {
			t.Fatal("carrier counter precision was lost")
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		selection := &sdk.IncidentEvidenceExportInput{Carrier: &sdk.IncidentCarrierInput{From: windows[tenant].From.Format(time.RFC3339Nano), To: windows[tenant].To.Format(time.RFC3339Nano)}}
		result, err := client.ExportIncidentEvidenceBytes(t.Context(), sdk.ExportIncidentEvidenceBytesRequest{Id: ids[tenant], Body: selection})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidence.Verify(result); err != nil {
			t.Fatal("carrier byte SDK changed signed bytes", err)
		}
		pkg.Attachments[0].Content = json.RawMessage(`{"summary":"changed after signing"}`)
		tampered, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidence.Verify(tampered); err == nil {
			t.Fatal("tampered carrier original verified")
		}
	}

	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		native := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			args := map[string]any{"incident_id": ids[tenant], "from": windows[tenant].From, "to": windows[tenant].To}
			var result struct {
				Package  string `json:"package"`
				Encoding string `json:"encoding"`
			}
			native(tenant, "incident_carrier_pack", args, &result, true)
			raw, err := base64.StdEncoding.Strict().DecodeString(result.Package)
			if err != nil || result.Encoding != "base64" {
				t.Fatal("native carrier byte encoding changed", err)
			}
			if manifest, err := evidence.Verify(raw); err != nil || manifest.Profile != "carrier" || manifest.Incident.ID != ids[tenant] {
				t.Fatal("native framing changed signed carrier originals", err)
			}
			args["tenant_id"] = f.tenants[1-lane]
			native(tenant, "incident_carrier_pack", args, nil, false)
			delete(args, "tenant_id")
			args["incident_id"] = ids[f.tenants[1-lane]]
			native(tenant, "incident_carrier_pack", args, nil, false)
		}
	}
	ca := filepath.Join(t.TempDir(), "carrier-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		selection, err := json.Marshal(incidentEvidenceExportInput{Carrier: func() *incident.CarrierInput { v := windows[tenant]; return &v }()})
		if err != nil {
			t.Fatal(err)
		}
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		var stdout, stderr bytes.Buffer
		if code := cli.RunWithStdin([]string{"incident", "export", ids[tenant], "--body-file", "-"}, getenv, bytes.NewReader(selection), &stdout, &stderr); code != 0 {
			t.Fatal("carrier CLI refused", code, stderr.String())
		}
		if _, err := evidence.Verify(stdout.Bytes()); err != nil {
			t.Fatal("carrier CLI changed signed bytes", err)
		}
	}
	// The same canonical interface parent must retain affected-prefix routing
	// without granting an unrelated router or the sibling's source identity.
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE incidents SET entity_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, ids[tenant], f.interfaceID)
			return err
		})
		code, raw := fetch(tenant, ids[tenant])
		if code != http.StatusOK {
			t.Fatal("canonical interface incident lost its router history", code, string(raw))
		}
		var pkg evidence.Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatal(err)
		}
		var pack incident.CarrierPack
		if len(pkg.Attachments) != 1 || json.Unmarshal(pkg.Attachments[0].Content, &pack) != nil || len(pack.Routing) != 1 || pack.Routing[0].Routing.RouterID != f.routerID {
			t.Fatal("canonical parent routing was omitted or substituted")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE incidents SET entity_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, ids[tenant], f.routerID)
			return err
		})
	}
	a, b := f.tenants[0], f.tenants[1]
	if code, raw := fetch(a, ids[b]); code == http.StatusOK || strings.Contains(string(raw), ids[b]) {
		t.Fatal("foreign carrier original disclosed")
	}
	proof.history.after = func() {
		proof.history.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND context_id=$2 AND source_kind='path_agent' AND agent_id=$3`, a, f.contextID, agents[a][0])
			return err
		})
	}
	if code, raw := fetch(a, ids[a]); code == http.StatusOK || strings.Contains(string(raw), "probectl.carrier-ticket.v1") {
		t.Fatal("late source withdrawal published retained carrier data", code)
	}
	if proof.history.after != nil {
		t.Fatal("source withdrawal boundary did not execute")
	}
	if code, _ := fetch(b, ids[b]); code != http.StatusOK {
		t.Fatal("primary withdrawal changed sibling carrier", code)
	}
}
