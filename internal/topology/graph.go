package topology

import (
	"sort"
	"sync"
	"time"
)

// Graph is a tenant-scoped, temporal, in-memory topology graph. Nodes and edges
// carry validity intervals [FirstSeen, LastSeen] that re-observation extends, so
// the graph can be queried as it was at any past time (an incident time). The
// versioning is designed in, not bolted on (S30 watch-out).
type Graph struct {
	tenant string
	mu     sync.RWMutex
	nodes  map[string]*Node
	edges  map[string]*Edge
}

// NewGraph returns an empty graph for a tenant.
func NewGraph(tenant string) *Graph {
	return &Graph{tenant: tenant, nodes: map[string]*Node{}, edges: map[string]*Edge{}}
}

// Tenant returns the graph's tenant.
func (g *Graph) Tenant() string { return g.tenant }

// UpsertNode records a node observation at time `at`, extending its validity
// interval and merging non-empty attributes.
func (g *Graph) UpsertNode(n Node, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, ok := g.nodes[n.ID]
	if !ok {
		n.FirstSeen, n.LastSeen = at, at
		if n.Attributes == nil {
			n.Attributes = map[string]string{}
		}
		g.nodes[n.ID] = &n
		return
	}
	if at.Before(cur.FirstSeen) {
		cur.FirstSeen = at
	}
	if at.After(cur.LastSeen) {
		cur.LastSeen = at
	}
	if n.Label != "" {
		cur.Label = n.Label
	}
	if n.Kind != "" {
		cur.Kind = n.Kind
	}
	for k, v := range n.Attributes {
		cur.Attributes[k] = v
	}
}

// UpsertEdge records a directed edge observation at time `at`.
func (g *Graph) UpsertEdge(e Edge, at time.Time) {
	if e.ID == "" {
		e.ID = EdgeID(e.From, e.Kind, e.To)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cur, ok := g.edges[e.ID]
	if !ok {
		e.FirstSeen, e.LastSeen = at, at
		if e.Attributes == nil {
			e.Attributes = map[string]string{}
		}
		g.edges[e.ID] = &e
		return
	}
	if at.Before(cur.FirstSeen) {
		cur.FirstSeen = at
	}
	if at.After(cur.LastSeen) {
		cur.LastSeen = at
	}
	if e.Label != "" {
		cur.Label = e.Label
	}
	for k, v := range e.Attributes {
		cur.Attributes[k] = v
	}
}

// SnapshotAt returns the nodes and edges valid at time `at` (FirstSeen ≤ at ≤
// LastSeen) — the graph as it was at that moment.
func (g *Graph) SnapshotAt(at time.Time) Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := Snapshot{Tenant: g.tenant, At: at}
	for _, n := range g.nodes {
		if validAt(n.FirstSeen, n.LastSeen, at) {
			s.Nodes = append(s.Nodes, *n)
		}
	}
	for _, e := range g.edges {
		if validAt(e.FirstSeen, e.LastSeen, at) {
			s.Edges = append(s.Edges, *e)
		}
	}
	sortSnapshot(&s)
	return s
}

// Latest returns the full current graph (every node and edge ever observed),
// timestamped with the most recent observation.
func (g *Graph) Latest() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := Snapshot{Tenant: g.tenant}
	for _, n := range g.nodes {
		s.Nodes = append(s.Nodes, *n)
		if n.LastSeen.After(s.At) {
			s.At = n.LastSeen
		}
	}
	for _, e := range g.edges {
		s.Edges = append(s.Edges, *e)
	}
	sortSnapshot(&s)
	return s
}

// Neighbors returns the ids adjacent to nodeID (either direction) over edges
// valid at time `at`.
func (g *Graph) Neighbors(nodeID string, at time.Time) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	seen := map[string]bool{}
	for _, e := range g.edges {
		if !validAt(e.FirstSeen, e.LastSeen, at) {
			continue
		}
		switch nodeID {
		case e.From:
			seen[e.To] = true
		case e.To:
			seen[e.From] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Traverse returns the shortest directed path (node ids) from `from` to `to`
// over edges valid at time `at`, or nil if unreachable. RCA traverses this.
func (g *Graph) Traverse(from, to string, at time.Time) []string {
	if from == to {
		return []string{from}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	adj := map[string][]string{}
	for _, e := range g.edges {
		if validAt(e.FirstSeen, e.LastSeen, at) {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}

	prev := map[string]string{}
	visited := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		nbrs := append([]string(nil), adj[cur]...)
		sort.Strings(nbrs)
		for _, n := range nbrs {
			if visited[n] {
				continue
			}
			visited[n] = true
			prev[n] = cur
			if n == to {
				return reconstruct(prev, from, to)
			}
			queue = append(queue, n)
		}
	}
	return nil
}

// NodeCount and EdgeCount report the full (all-time) graph size.
func (g *Graph) NodeCount() int { g.mu.RLock(); defer g.mu.RUnlock(); return len(g.nodes) }
func (g *Graph) EdgeCount() int { g.mu.RLock(); defer g.mu.RUnlock(); return len(g.edges) }

func validAt(first, last, at time.Time) bool {
	return !at.Before(first) && !at.After(last)
}

func reconstruct(prev map[string]string, from, to string) []string {
	path := []string{to}
	for cur := to; cur != from; {
		p := prev[cur]
		path = append(path, p)
		cur = p
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

func sortSnapshot(s *Snapshot) {
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].ID < s.Nodes[j].ID })
	sort.Slice(s.Edges, func(i, j int) bool { return s.Edges[i].ID < s.Edges[j].ID })
}
