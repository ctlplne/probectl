// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var watT = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

// diamondStore builds the canonical what-if fixture:
//
//	agent:a ── hop:r1 ──┬── hop:r2 ──┐
//	                    │            ├── hop:r4 ── host:web  (two routes)
//	                    └── hop:r3 ──┘
//	agent:a ── hop:r1 ── hop:r5 ── host:db        (single route)
//	service edges: api → db-svc, web-svc → api
//	routing: AS64500 originates 198.51.100.0/24
//	device: core-sw carries r1
func diamondStore() *MemoryStore {
	s := NewMemoryStore()
	s.ObservePath("t1", PathInput{
		AgentID: "a", Target: "web", TargetIP: "203.0.113.10",
		Hops: []string{"10.0.0.1", "10.0.0.2", "10.0.0.4"},
		Links: []Link{{From: "10.0.0.1", To: "10.0.0.2"}, {From: "10.0.0.2", To: "10.0.0.4"},
			{From: "10.0.0.1", To: "10.0.0.3"}, {From: "10.0.0.3", To: "10.0.0.4"}},
	}, watT)
	s.ObservePath("t1", PathInput{
		AgentID: "a", Target: "db", TargetIP: "203.0.113.20",
		Hops:  []string{"10.0.0.1", "10.0.0.5"},
		Links: []Link{{From: "10.0.0.1", To: "10.0.0.5"}},
	}, watT)
	s.ObserveServiceEdge("t1", ServiceEdgeInput{Source: "api", Destination: "db-svc", DestPort: 5432, Transport: "tcp"}, watT)
	s.ObserveServiceEdge("t1", ServiceEdgeInput{Source: "web-svc", Destination: "api", DestPort: 8080, Transport: "tcp"}, watT)
	s.ObserveRouting("t1", RoutingInput{Prefix: "198.51.100.0/24", OriginASN: 64500}, watT)
	s.observeDevice("t1", DeviceInput{Address: "192.0.2.250", Name: "core-sw", InterfaceIPs: []string{"10.0.0.1"}}, watT)
	return s
}

// The sprint's named test: simulate a link failure → the predicted impacted
// paths match expectation (one route survives the diamond; the spur breaks).
func TestWhatIfLinkFailure(t *testing.T) {
	s := diamondStore()

	// Fail the r1→r2 LINK: web survives via r3 (rerouted), db unaffected.
	imp, err := Simulate(s, "t1", EdgeID("hop:10.0.0.1", EdgePath, "hop:10.0.0.2"), watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if imp.TargetKind != "edge" {
		t.Fatalf("target kind = %s", imp.TargetKind)
	}
	if len(imp.BrokenPaths) != 0 {
		t.Fatalf("link failure broke paths unexpectedly: %+v", imp.BrokenPaths)
	}
	if len(imp.ReroutedPaths) != 1 || imp.ReroutedPaths[0].To != "host:203.0.113.10" {
		t.Fatalf("rerouted = %+v", imp.ReroutedPaths)
	}
	if len(imp.ImpactedTests) != 1 || imp.ImpactedTests[0].AgentID != "agent:a" ||
		imp.ImpactedTests[0].Target != "host:203.0.113.10" || imp.ImpactedTests[0].Status != PathRerouted {
		t.Fatalf("impacted tests = %+v", imp.ImpactedTests)
	}
	alt := strings.Join(imp.ReroutedPaths[0].AltRoute, "→")
	if !strings.Contains(alt, "hop:10.0.0.3") {
		t.Fatalf("alternate route must go via r3: %s", alt)
	}

	// Fail hop r5: the db path has NO alternate → broken.
	imp, err = Simulate(s, "t1", "hop:10.0.0.5", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.BrokenPaths) != 1 || imp.BrokenPaths[0].To != "host:203.0.113.20" {
		t.Fatalf("broken = %+v", imp.BrokenPaths)
	}
	if len(imp.ReroutedPaths) != 0 {
		t.Fatalf("unexpected reroutes: %+v", imp.ReroutedPaths)
	}
	// The dead-end target falls off the map entirely.
	if !contains(imp.Disconnected, "host:203.0.113.20") {
		t.Fatalf("disconnected = %+v", imp.Disconnected)
	}

	// Fail r1 (the shared first hop): EVERYTHING breaks.
	imp, err = Simulate(s, "t1", "hop:10.0.0.1", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.BrokenPaths) != 2 {
		t.Fatalf("shared-hop failure must break both paths: %+v", imp.BrokenPaths)
	}
}

func TestWhatIfServiceAndRoutingImpact(t *testing.T) {
	s := diamondStore()

	// Fail db-svc: api (direct caller) and web-svc (transitive) are impacted.
	imp, err := Simulate(s, "t1", "service:db-svc", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"service:api", "service:db-svc", "service:web-svc"}
	if fmt.Sprint(imp.ImpactedServices) != fmt.Sprint(want) {
		t.Fatalf("impacted services = %v, want %v", imp.ImpactedServices, want)
	}

	// Fail the origin AS: its prefix is impacted.
	imp, err = Simulate(s, "t1", "as:64500", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.ImpactedPrefixes) != 1 || imp.ImpactedPrefixes[0] != "prefix:198.51.100.0/24" {
		t.Fatalf("impacted prefixes = %v", imp.ImpactedPrefixes)
	}
}

func TestWhatIfCoverageHonesty(t *testing.T) {
	s := diamondStore()
	imp, err := Simulate(s, "t1", "hop:10.0.0.1", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := imp.Coverage
	if c.PathEdges == 0 || c.FlowEdges != 2 || c.RoutingEdges != 1 || c.DeviceEdges != 1 {
		t.Fatalf("coverage = %+v", c)
	}
	// SLO engine not wired → reported, not silent.
	if !containsSub(c.Notes, "slo impact not wired") {
		t.Fatalf("notes = %v", c.Notes)
	}
	if imp.Confidence.Level != "high" || imp.Confidence.Score != 80 ||
		!strings.Contains(imp.Confidence.Basis, "4 of 5") {
		t.Fatalf("confidence = %+v", imp.Confidence)
	}

	// A path-only graph reports the missing planes.
	bare := NewMemoryStore()
	bare.ObservePath("t1", PathInput{AgentID: "a", Target: "x", TargetIP: "203.0.113.1",
		Hops: []string{"10.0.0.9"}, Links: nil}, watT)
	imp, err = Simulate(bare, "t1", "hop:10.0.0.9", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no flow-plane", "no routing-plane", "no device→hop"} {
		if !containsSub(imp.Coverage.Notes, want) {
			t.Fatalf("coverage notes missing %q: %v", want, imp.Coverage.Notes)
		}
	}
	if imp.Confidence.Level != "low" || imp.Confidence.Score != 20 {
		t.Fatalf("path-only confidence = %+v", imp.Confidence)
	}
}

type fixedSLO struct{ slos []string }

func (f fixedSLO) ImpactedSLOs(string, []string, []string) []string { return f.slos }

func TestWhatIfSLOSeamAndUnknownTarget(t *testing.T) {
	s := diamondStore()
	imp, err := Simulate(s, "t1", "service:db-svc", watT, fixedSLO{slos: []string{"slo:checkout-availability"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.ImpactedSLOs) != 1 || imp.ImpactedSLOs[0] != "slo:checkout-availability" {
		t.Fatalf("slos = %v", imp.ImpactedSLOs)
	}
	if containsSub(imp.Coverage.Notes, "slo impact not wired") {
		t.Fatalf("wired SLO source still flagged: %v", imp.Coverage.Notes)
	}
	if imp.Confidence.Score != 100 || imp.Confidence.Level != "high" {
		t.Fatalf("fully wired confidence = %+v", imp.Confidence)
	}

	// Unknown target fails closed — never an empty "no impact".
	if _, err := Simulate(s, "t1", "hop:does-not-exist", watT, nil); err == nil {
		t.Fatal("unknown target simulated without error")
	}
}

// Temporal: simulating at a time before an edge existed uses the graph AS IT
// WAS — the versioned-graph contract.
func TestWhatIfIsTemporal(t *testing.T) {
	s := NewMemoryStore()
	early := watT
	late := watT.Add(time.Hour)
	s.ObservePath("t1", PathInput{AgentID: "a", Target: "x", TargetIP: "203.0.113.1",
		Hops: []string{"10.0.0.1"}, Links: nil}, early)
	// LATER the original route is re-observed AND an alternate appears.
	s.ObservePath("t1", PathInput{AgentID: "a", Target: "x", TargetIP: "203.0.113.1",
		Hops: []string{"10.0.0.1"}, Links: nil}, late)
	s.ObservePath("t1", PathInput{AgentID: "a", Target: "x", TargetIP: "203.0.113.1",
		Hops: []string{"10.0.0.2"}, Links: nil}, late)

	imp, err := Simulate(s, "t1", "hop:10.0.0.1", early, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.BrokenPaths) != 1 {
		t.Fatalf("at %s the only route must break: %+v", early, imp.BrokenPaths)
	}
	imp, err = Simulate(s, "t1", "hop:10.0.0.1", late, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.ReroutedPaths) != 1 || len(imp.BrokenPaths) != 0 {
		t.Fatalf("at %s the late route must survive: %+v / %+v", late, imp.BrokenPaths, imp.ReroutedPaths)
	}
}

// Tenant isolation: a simulation can never see another tenant's graph.
func TestWhatIfTenantIsolation(t *testing.T) {
	s := diamondStore()
	if _, err := Simulate(s, "other-tenant", "hop:10.0.0.1", watT, nil); err == nil {
		t.Fatal("another tenant's node resolved in an empty graph")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func containsSub(list []string, sub string) bool {
	for _, v := range list {
		if strings.Contains(v, sub) {
			return true
		}
	}
	return false
}
