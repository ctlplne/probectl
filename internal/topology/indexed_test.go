// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

import (
	"fmt"
	"testing"
	"time"
)

// Equivalence: the indexed engine answers every query identically to the
// reference MemoryStore — the migration is transparent (the S43 contract).
func TestIndexedStoreEquivalence(t *testing.T) {
	seed := func(t *testing.T, s Store) {
		t.Helper()
		g, err := s.ForTenant("t1")
		if err != nil {
			t.Fatal(err)
		}
		g.ObservePath(PathInput{AgentID: "a", Target: "web", TargetIP: "203.0.113.10",
			Hops: []string{"10.0.0.1", "10.0.0.2", "10.0.0.4"},
			Links: []Link{{From: "10.0.0.1", To: "10.0.0.2"}, {From: "10.0.0.2", To: "10.0.0.4"},
				{From: "10.0.0.1", To: "10.0.0.3"}, {From: "10.0.0.3", To: "10.0.0.4"}}}, watT)
		g.ObserveServiceEdge(ServiceEdgeInput{Source: "api", Destination: "db"}, watT)
		g.ObserveRouting(RoutingInput{Prefix: "198.51.100.0/24", OriginASN: 64500}, watT)
		g.ObserveDevice(DeviceInput{Address: "192.0.2.250", InterfaceIPs: []string{"10.0.0.1"}}, watT)
	}
	mem, idx := NewMemoryStore(), NewIndexedStore()
	seed(t, mem)
	seed(t, idx)

	for _, node := range []string{"agent:a", "hop:10.0.0.1", "hop:10.0.0.4", "service:api", "device:192.0.2.250"} {
		m := mem.Neighbors("t1", node, watT)
		i := idx.Neighbors("t1", node, watT)
		if fmt.Sprint(m) != fmt.Sprint(i) {
			t.Fatalf("Neighbors(%s): memory=%v indexed=%v", node, m, i)
		}
	}
	m := mem.Traverse("t1", "agent:a", "host:203.0.113.10", watT)
	i := idx.Traverse("t1", "agent:a", "host:203.0.113.10", watT)
	if fmt.Sprint(m) != fmt.Sprint(i) {
		t.Fatalf("Traverse: memory=%v indexed=%v", m, i)
	}
	// Temporal validity flows from the single source of truth.
	if got := idx.Neighbors("t1", "agent:a", watT.Add(-time.Hour)); len(got) != 0 {
		t.Fatalf("neighbors before first observation = %v", got)
	}
	// Snapshot parity.
	ms, is := mem.Latest("t1"), idx.Latest("t1")
	if len(ms.Nodes) != len(is.Nodes) || len(ms.Edges) != len(is.Edges) {
		t.Fatalf("snapshot sizes differ: memory %d/%d indexed %d/%d",
			len(ms.Nodes), len(ms.Edges), len(is.Nodes), len(is.Edges))
	}
	// What-if runs identically over either engine (Snapshot-driven).
	mImp, err := Simulate(mem, "t1", "hop:10.0.0.2", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	iImp, err := Simulate(idx, "t1", "hop:10.0.0.2", watT, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(mImp.ReroutedPaths) != fmt.Sprint(iImp.ReroutedPaths) ||
		fmt.Sprint(mImp.BrokenPaths) != fmt.Sprint(iImp.BrokenPaths) {
		t.Fatalf("what-if diverges across engines:\nmemory:  %+v / %+v\nindexed: %+v / %+v",
			mImp.BrokenPaths, mImp.ReroutedPaths, iImp.BrokenPaths, iImp.ReroutedPaths)
	}
}

// The S43 scale test: an XL graph (a multi-site fabric — ~31k nodes, ~46k
// edges) on the dedicated engine. Traverse and a full what-if must stay
// interactive (well under the API budget), and the what-if prediction must
// stay CORRECT at that scale: failing one site's aggregation hop breaks
// exactly that site's leaf targets.
func TestIndexedStoreXLScaleWhatIf(t *testing.T) {
	s := NewIndexedStore()
	const sites = 30
	const leavesPerSite = 500

	for site := 0; site < sites; site++ {
		agg := fmt.Sprintf("10.%d.0.1", site)
		// agent → site aggregation hop → 500 leaf hops → 500 hosts
		for leaf := 0; leaf < leavesPerSite; leaf++ {
			leafIP := fmt.Sprintf("10.%d.1.%d", site, leaf)
			s.ObservePath("t1", PathInput{
				AgentID: fmt.Sprintf("agent-%d", site),
				Target:  fmt.Sprintf("svc-%d-%d", site, leaf), TargetIP: fmt.Sprintf("203.%d.%d.%d", site, leaf/250, leaf%250+1),
				Hops:  []string{agg, leafIP},
				Links: []Link{{From: agg, To: leafIP}},
			}, watT)
		}
	}

	snap := s.Latest("t1")
	if len(snap.Nodes) < 30000 || len(snap.Edges) < 30000 {
		t.Fatalf("fixture too small: %d nodes / %d edges", len(snap.Nodes), len(snap.Edges))
	}

	start := time.Now()
	route := s.Traverse("t1", "agent:agent-7", "host:203.7.0.124", watT)
	if route == nil {
		t.Fatal("traverse found no route on the XL graph")
	}
	traverseDur := time.Since(start)

	start = time.Now()
	imp, err := Simulate(s, "t1", "hop:10.7.0.1", watT, nil) // site 7's aggregation hop
	if err != nil {
		t.Fatal(err)
	}
	simDur := time.Since(start)

	// Correctness at scale: exactly site 7's targets break, no reroutes.
	if len(imp.BrokenPaths) != leavesPerSite {
		t.Fatalf("broken = %d, want %d", len(imp.BrokenPaths), leavesPerSite)
	}
	if len(imp.ReroutedPaths) != 0 {
		t.Fatalf("unexpected reroutes at scale: %d", len(imp.ReroutedPaths))
	}
	for _, p := range imp.BrokenPaths {
		if p.From != "agent:agent-7" {
			t.Fatalf("impact leaked outside the failed site: %+v", p)
		}
	}

	// Interactivity budget (generous for CI hardware; locally ~10-100x faster).
	if traverseDur > 2*time.Second || simDur > 10*time.Second {
		t.Fatalf("XL latencies: traverse=%s whatif=%s", traverseDur, simDur)
	}
	t.Logf("XL scale: %d nodes / %d edges; traverse=%s whatif=%s",
		len(snap.Nodes), len(snap.Edges), traverseDur, simDur)
}
