// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

// seededTopology builds a two-route diamond for the default tenant and a
// separate graph for another tenant (the isolation probe).
func seededTopology() *topology.IndexedStore {
	s := topology.NewIndexedStore()
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	tid := tenancy.DefaultTenantID.String()
	s.ObservePath(tid, topology.PathInput{
		AgentID: "probe-1", Target: "web", TargetIP: "203.0.113.10",
		Hops: []string{"10.0.0.1", "10.0.0.2", "10.0.0.4"},
		Links: []topology.Link{{From: "10.0.0.1", To: "10.0.0.2"}, {From: "10.0.0.2", To: "10.0.0.4"},
			{From: "10.0.0.1", To: "10.0.0.3"}, {From: "10.0.0.3", To: "10.0.0.4"}},
	}, at)
	s.ObserveServiceEdge(tid, topology.ServiceEdgeInput{Source: "api", Destination: "db", DestPort: 5432}, at)
	s.ObservePath("00000000-0000-0000-0000-000000000002", topology.PathInput{
		AgentID: "other-agent", Target: "secret", TargetIP: "198.51.100.99",
		Hops: []string{"172.16.0.1"},
	}, at)
	return s
}

func TestTopologyEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).WithTopology(seededTopology())

	rec := do(srv, http.MethodGet, "/v1/topology")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Running bool               `json:"topology_running"`
		Nodes   []topology.VizNode `json:"nodes"`
		Edges   []topology.VizEdge `json:"edges"`
		Cover   topology.Coverage  `json:"coverage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Nodes) == 0 || len(resp.Edges) == 0 {
		t.Fatalf("resp = %+v", resp)
	}
	// TENANT ISOLATION: the other tenant's nodes never appear.
	for _, n := range resp.Nodes {
		if strings.Contains(n.ID, "172.16.0.1") || strings.Contains(n.Label, "secret") {
			t.Fatalf("cross-tenant node leaked: %+v", n)
		}
	}
	// Coverage honesty present (no routing/device planes seeded).
	joined := strings.Join(resp.Cover.Notes, " | ")
	if !strings.Contains(joined, "no routing-plane") {
		t.Fatalf("coverage notes = %v", resp.Cover.Notes)
	}
}

func TestTopologyHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{}) // no WithTopology

	rec := do(srv, http.MethodGet, "/v1/topology")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"topology_running":false`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestWhatIfEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).WithTopology(seededTopology())

	// Fail hop r2: the diamond reroutes via r3.
	rec := doJSONReq(srv, http.MethodPost, "/v1/topology/whatif",
		`{"target":"hop:10.0.0.2","at":"2026-06-04T12:00:00Z"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var imp topology.Impact
	if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.TargetKind != "hop" || len(imp.ReroutedPaths) != 1 || len(imp.BrokenPaths) != 0 {
		t.Fatalf("impact = %+v", imp)
	}
	if len(imp.ImpactedTests) != 1 || imp.Confidence.Score == 0 || imp.Confidence.Basis == "" {
		t.Fatalf("test/confidence contract missing: %+v", imp)
	}
	if !strings.Contains(strings.Join(imp.ReroutedPaths[0].AltRoute, "→"), "hop:10.0.0.3") {
		t.Fatalf("alt route = %v", imp.ReroutedPaths[0].AltRoute)
	}

	// Unknown target → 404 (fail closed), and another tenant's node is
	// unknown by construction (isolation).
	for _, target := range []string{"hop:does-not-exist", "hop:172.16.0.1"} {
		rec = doJSONReq(srv, http.MethodPost, "/v1/topology/whatif", `{"target":"`+target+`"}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("target %s: status = %d, want 404", target, rec.Code)
		}
	}

	// Validation: missing target, bad time.
	if rec = doJSONReq(srv, http.MethodPost, "/v1/topology/whatif", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing target: %d", rec.Code)
	}
	if rec = doJSONReq(srv, http.MethodPost, "/v1/topology/whatif", `{"target":"x","at":"yesterday"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad at: %d", rec.Code)
	}
}

// TestTopologySimulationObserveOnlyExport proves the downloadable receipt is
// the same dry-run calculation, carries an attachment disposition, cannot see
// another tenant's target, and leaves the versioned graph byte-for-byte
// unchanged.
func TestTopologySimulationObserveOnlyExport(t *testing.T) {
	store := seededTopology()
	graph, err := store.ForTenant(tenancy.DefaultTenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	before := graph.Latest()
	srv := testServer(fakePinger{}).WithTopology(store)

	rec := do(srv, http.MethodGet,
		"/v1/topology/whatif/export?target=hop%3A10.0.0.2&at=2026-06-04T12%3A00%3A00Z")
	if rec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") ||
		!strings.Contains(got, "probectl-topology-whatif.json") {
		t.Fatalf("content disposition = %q", got)
	}
	var impact topology.Impact
	if err := json.Unmarshal(rec.Body.Bytes(), &impact); err != nil {
		t.Fatal(err)
	}
	if impact.Target != "hop:10.0.0.2" || len(impact.ReroutedPaths) != 1 {
		t.Fatalf("export impact = %+v", impact)
	}
	if after := graph.Latest(); !reflect.DeepEqual(after, before) {
		t.Fatalf("observe-only simulation mutated topology:\nbefore=%+v\nafter=%+v", before, after)
	}

	// This target exists only in the other tenant's graph. A scoped export
	// returns the same not-found result as an unknown local target.
	rec = do(srv, http.MethodGet, "/v1/topology/whatif/export?target=hop%3A172.16.0.1")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant export = %d, want 404", rec.Code)
	}
}
