// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	// recent collects edge upserts since the last drainRecentEdges call — the
	// O(touched) feed for the S43 indexed engine's adjacency indexes.
	recent []Edge

	// Bounds (SCALE-004 / CORRECT-014). maxNodes/maxEdges cap per-tenant memory:
	// when an upsert of a NEW element would exceed the cap, the least-recently-
	// seen element is evicted (a runaway agent minting churn identities can't
	// grow the graph without bound). staleness, when > 0, is the horizon Latest()
	// applies: elements not re-observed within it are treated as gone, so the
	// "current" graph reflects what is actually live instead of accreting every
	// node/edge ever seen. Zero values keep the previous unbounded behavior.
	maxNodes  int
	maxEdges  int
	staleness time.Duration
	now       func() time.Time // injectable clock (tests)
}

// NewGraph returns an empty graph for a tenant.
func NewGraph(tenant string) *Graph {
	return &Graph{tenant: tenant, nodes: map[string]*Node{}, edges: map[string]*Edge{}, now: time.Now}
}

// SetBounds configures per-tenant node/edge caps and the Latest() staleness
// horizon (SCALE-004 / CORRECT-014). A non-positive value leaves that bound
// unset (unbounded / no horizon). Safe to call at construction.
func (g *Graph) SetBounds(maxNodes, maxEdges int, staleness time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxNodes, g.maxEdges, g.staleness = maxNodes, maxEdges, staleness
}

// evictOldestNodeLocked drops the least-recently-seen node when at the cap.
// Caller holds g.mu.
func (g *Graph) evictOldestNodeLocked() {
	var oldestID string
	var oldest time.Time
	for id, n := range g.nodes {
		if oldestID == "" || n.LastSeen.Before(oldest) {
			oldestID, oldest = id, n.LastSeen
		}
	}
	if oldestID != "" {
		delete(g.nodes, oldestID)
	}
}

// evictOldestEdgeLocked drops the least-recently-seen edge when at the cap.
func (g *Graph) evictOldestEdgeLocked() {
	var oldestID string
	var oldest time.Time
	for id, e := range g.edges {
		if oldestID == "" || e.LastSeen.Before(oldest) {
			oldestID, oldest = id, e.LastSeen
		}
	}
	if oldestID != "" {
		delete(g.edges, oldestID)
	}
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
		if g.maxNodes > 0 && len(g.nodes) >= g.maxNodes {
			g.evictOldestNodeLocked() // SCALE-004: bound per-tenant node count
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
		if g.maxEdges > 0 && len(g.edges) >= g.maxEdges {
			g.evictOldestEdgeLocked() // SCALE-004: bound per-tenant edge count
		}
		g.edges[e.ID] = &e
		g.recent = append(g.recent, Edge{ID: e.ID, From: e.From, To: e.To, Kind: e.Kind})
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
	// CORRECT-014: when a staleness horizon is set, "latest" means "still live"
	// — elements not re-observed within the horizon are excluded, so the graph
	// reflects current reality instead of every node/edge ever seen.
	var cutoff time.Time
	if g.staleness > 0 {
		clock := g.now
		if clock == nil {
			clock = time.Now
		}
		cutoff = clock().Add(-g.staleness)
	}
	fresh := func(lastSeen time.Time) bool { return cutoff.IsZero() || !lastSeen.Before(cutoff) }
	for _, n := range g.nodes {
		if !fresh(n.LastSeen) {
			continue
		}
		s.Nodes = append(s.Nodes, *n)
		if n.LastSeen.After(s.At) {
			s.At = n.LastSeen
		}
	}
	for _, e := range g.edges {
		if !fresh(e.LastSeen) {
			continue
		}
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

// PruneBefore removes graph elements whose last observation is older than the
// cutoff. It is the store-owned age-retention clock for derived topology
// identity labels: after pruning, stale nodes/edges are gone from Latest,
// SnapshotAt, Neighbors, and Traverse rather than merely hidden by a handler.
func (g *Graph) PruneBefore(cutoff time.Time) (nodesDeleted, edgesDeleted int) {
	if cutoff.IsZero() {
		return 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, e := range g.edges {
		if e.LastSeen.Before(cutoff) {
			delete(g.edges, id)
			edgesDeleted++
		}
	}
	for id, n := range g.nodes {
		if n.LastSeen.Before(cutoff) {
			delete(g.nodes, id)
			nodesDeleted++
		}
	}
	for id, e := range g.edges {
		if _, ok := g.nodes[e.From]; !ok {
			delete(g.edges, id)
			edgesDeleted++
			continue
		}
		if _, ok := g.nodes[e.To]; !ok {
			delete(g.edges, id)
			edgesDeleted++
		}
	}
	if len(g.recent) > 0 {
		kept := g.recent[:0]
		for _, e := range g.recent {
			if _, ok := g.edges[e.ID]; ok {
				kept = append(kept, e)
			}
		}
		g.recent = kept
	}
	return nodesDeleted, edgesDeleted
}

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

// drainRecentEdges returns (and clears) the edges upserted since the last
// call — consumed by the S43 indexed engine to keep adjacency indexes in
// step without rescanning the edge set.
func (g *Graph) drainRecentEdges() []Edge {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.recent
	g.recent = nil
	return out
}

func (g *Graph) allEdges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, *e)
	}
	return out
}

// edgeValidAt reports whether the edge with id exists and is valid at time at.
func (g *Graph) edgeValidAt(id string, at time.Time) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.edges[id]
	return ok && validAt(e.FirstSeen, e.LastSeen, at)
}
