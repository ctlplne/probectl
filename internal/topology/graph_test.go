package topology

import (
	"strings"
	"testing"
	"time"
)

func TestGraphTemporalSnapshot(t *testing.T) {
	g := NewGraph("t1")
	t1, t2 := time.Unix(100, 0), time.Unix(200, 0)
	g.UpsertNode(Node{ID: "a", Kind: NodeAgent}, t1)
	g.UpsertNode(Node{ID: "b", Kind: NodeHop}, t1)
	g.UpsertEdge(Edge{From: "a", To: "b", Kind: EdgePath}, t1)
	// c + its edge only ever observed at t2.
	g.UpsertNode(Node{ID: "c", Kind: NodeHop}, t2)
	g.UpsertEdge(Edge{From: "b", To: "c", Kind: EdgePath}, t2)

	at1 := g.SnapshotAt(t1)
	if len(at1.Nodes) != 2 || len(at1.Edges) != 1 {
		t.Fatalf("snapshot@t1 = %d nodes / %d edges, want 2 / 1", len(at1.Nodes), len(at1.Edges))
	}
	for _, n := range at1.Nodes {
		if n.ID == "c" {
			t.Error("c must not appear in snapshot@t1 (observed later)")
		}
	}

	latest := g.Latest()
	if len(latest.Nodes) != 3 || len(latest.Edges) != 2 {
		t.Errorf("latest = %d nodes / %d edges, want 3 / 2", len(latest.Nodes), len(latest.Edges))
	}
}

func TestGraphReObservationExtendsIntervalAndMergesAttrs(t *testing.T) {
	g := NewGraph("t1")
	t1, mid, t2 := time.Unix(100, 0), time.Unix(200, 0), time.Unix(300, 0)
	g.UpsertNode(Node{ID: "x", Kind: NodeHop}, t1)
	g.UpsertNode(Node{ID: "x", Kind: NodeHop, Attributes: map[string]string{"asn": "64500"}}, t2)

	s := g.SnapshotAt(mid)
	if len(s.Nodes) != 1 {
		t.Fatalf("snapshot@mid = %d nodes, want 1 (interval extended)", len(s.Nodes))
	}
	if s.Nodes[0].Attributes["asn"] != "64500" {
		t.Errorf("re-observation should merge attributes, got %+v", s.Nodes[0].Attributes)
	}
}

func TestGraphTraverseAndNeighbors(t *testing.T) {
	g := NewGraph("t1")
	at := time.Unix(100, 0)
	for _, e := range [][2]string{{"a", "b"}, {"b", "c"}, {"c", "d"}, {"a", "e"}} {
		g.UpsertEdge(Edge{From: e[0], To: e[1], Kind: EdgePath}, at)
	}
	if got := strings.Join(g.Traverse("a", "d", at), "->"); got != "a->b->c->d" {
		t.Errorf("traverse a..d = %q, want a->b->c->d", got)
	}
	if p := g.Traverse("d", "a", at); p != nil {
		t.Errorf("directed traverse d..a should be unreachable, got %v", p)
	}
	if n := g.Neighbors("a", at); len(n) != 2 {
		t.Errorf("neighbors(a) = %v, want 2 (b, e)", n)
	}
	// Temporal: nothing is reachable before the edges existed.
	if p := g.Traverse("a", "d", time.Unix(50, 0)); p != nil {
		t.Errorf("traverse before edges existed should be empty, got %v", p)
	}
}
