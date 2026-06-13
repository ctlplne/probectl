// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

import (
	"fmt"
	"testing"
	"time"
)

// SCALE-004: per-tenant node/edge caps bound memory — a runaway churn of new
// identities evicts the least-recently-seen instead of growing without bound.
func TestGraphNodeCapEvictsOldest(t *testing.T) {
	g := NewGraph("t-a")
	g.SetBounds(3, 100, 0)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5; i++ {
		g.UpsertNode(Node{ID: fmt.Sprintf("n%d", i)}, base.Add(time.Duration(i)*time.Minute))
	}
	s := g.Latest()
	if len(s.Nodes) != 3 {
		t.Fatalf("node cap not enforced: %d nodes, want 3", len(s.Nodes))
	}
	// The three most-recently-seen survive (n2, n3, n4); n0/n1 evicted.
	ids := map[string]bool{}
	for _, n := range s.Nodes {
		ids[n.ID] = true
	}
	if ids["n0"] || ids["n1"] {
		t.Fatalf("least-recently-seen nodes were not evicted: %v", ids)
	}
}

// CORRECT-014: with a staleness horizon, Latest() returns only elements
// re-observed within the horizon — the "current" graph is what is live, not
// every node ever seen.
func TestGraphStalenessHorizon(t *testing.T) {
	g := NewGraph("t-a")
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	g.SetBounds(0, 0, 10*time.Minute)

	g.UpsertNode(Node{ID: "stale"}, now.Add(-30*time.Minute)) // outside horizon
	g.UpsertNode(Node{ID: "fresh"}, now.Add(-1*time.Minute))  // inside horizon

	s := g.Latest()
	if len(s.Nodes) != 1 || s.Nodes[0].ID != "fresh" {
		t.Fatalf("staleness horizon not applied: got %+v, want only [fresh]", s.Nodes)
	}

	// SnapshotAt still sees history (temporal queries are unaffected).
	hist := g.SnapshotAt(now.Add(-30 * time.Minute))
	if len(hist.Nodes) == 0 {
		t.Fatal("historical SnapshotAt must still see the stale node")
	}
}
