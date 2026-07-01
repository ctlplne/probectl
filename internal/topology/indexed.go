// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

// IndexedStore is the S43 dedicated-graph-engine option: the same Store
// contract as MemoryStore, backed by forward/reverse adjacency indexes so
// Neighbors and Traverse are proportional to a node's degree instead of the
// whole edge set — the L/XL-scale behavior the sprint requires. The migration
// is TRANSPARENT: it is selected by configuration behind the S30 query API;
// no caller changes. (An external graph-database adapter implements this same
// interface when a deployment outgrows a single process.)

import (
	"sort"
	"sync"
	"time"
)

// IndexedStore manages per-tenant indexed graphs.
type IndexedStore struct {
	mu     sync.Mutex
	graphs map[string]*indexedGraph
}

// NewIndexedStore returns an empty indexed store.
func NewIndexedStore() *IndexedStore {
	return &IndexedStore{graphs: map[string]*indexedGraph{}}
}

// ForTenant returns an indexed graph handle bound to one tenant.
func (s *IndexedStore) ForTenant(tenant string) (TenantStore, error) {
	return bindTenant(s, tenant)
}

// DeleteTenant drops the tenant's entire indexed graph (every snapshot/
// version — S-T5 verifiable erasure, U-027) and reports whether one existed.
func (s *IndexedStore) DeleteTenant(tenant string) int {
	if _, err := normalizeTenant(tenant); err != nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.graphs[tenant]; !ok {
		return 0
	}
	delete(s.graphs, tenant)
	return 1
}

// PruneTenantBefore removes stale derived topology identity labels for one
// tenant and rebuilds the adjacency indexes from the retained edge set.
func (s *IndexedStore) PruneTenantBefore(tenant string, cutoff time.Time) int {
	if _, err := normalizeTenant(tenant); err != nil {
		return 0
	}
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return 0
	}
	return g.pruneBefore(cutoff)
}

func (s *IndexedStore) graph(tenant string) *indexedGraph {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.graphs[tenant]
	if !ok {
		g = newIndexedGraph(tenant)
		s.graphs[tenant] = g
	}
	return g
}

func (s *IndexedStore) graphIfExists(tenant string) (*indexedGraph, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.graphs[tenant]
	return g, ok
}

// ObservePath is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant and call TenantStore.ObservePath instead.
func (s *IndexedStore) ObservePath(tenant string, in PathInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observePathTenant(tenant, in, at)
}

// ObserveServiceEdge is a concrete compatibility helper. Tenant-owned
// production callers should bind ForTenant first.
func (s *IndexedStore) ObserveServiceEdge(tenant string, in ServiceEdgeInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeServiceEdgeTenant(tenant, in, at)
}

// ObserveRouting is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *IndexedStore) ObserveRouting(tenant string, in RoutingInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeRoutingTenant(tenant, in, at)
}

// ObserveDevice is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *IndexedStore) ObserveDevice(tenant string, in DeviceInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeDeviceTenant(tenant, in, at)
}

// SnapshotAt is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *IndexedStore) SnapshotAt(tenant string, at time.Time) Snapshot {
	if _, err := normalizeTenant(tenant); err != nil {
		return Snapshot{At: at}
	}
	return s.snapshotAtTenant(tenant, at)
}

// Latest is a concrete compatibility helper. Tenant-owned production callers
// should bind ForTenant first.
func (s *IndexedStore) Latest(tenant string) Snapshot {
	if _, err := normalizeTenant(tenant); err != nil {
		return Snapshot{}
	}
	return s.latestTenant(tenant)
}

// Neighbors is a concrete compatibility helper via the adjacency indexes
// (degree-proportional). Tenant-owned production callers should bind ForTenant
// first.
func (s *IndexedStore) Neighbors(tenant, nodeID string, at time.Time) []string {
	if _, err := normalizeTenant(tenant); err != nil {
		return nil
	}
	return s.neighborsTenant(tenant, nodeID, at)
}

// Traverse is a concrete compatibility helper for the shortest directed route
// via the forward index. Tenant-owned production callers should bind ForTenant
// first.
func (s *IndexedStore) Traverse(tenant, from, to string, at time.Time) []string {
	if _, err := normalizeTenant(tenant); err != nil {
		return nil
	}
	return s.traverseTenant(tenant, from, to, at)
}

func (s *IndexedStore) observePathTenant(tenant string, in PathInput, at time.Time) {
	s.graph(tenant).observe(func(g *Graph) { g.ObservePath(in, at) })
}

func (s *IndexedStore) observeServiceEdgeTenant(tenant string, in ServiceEdgeInput, at time.Time) {
	s.graph(tenant).observe(func(g *Graph) { g.ObserveServiceEdge(in, at) })
}

func (s *IndexedStore) observeRoutingTenant(tenant string, in RoutingInput, at time.Time) {
	s.graph(tenant).observe(func(g *Graph) { g.ObserveRouting(in, at) })
}

func (s *IndexedStore) observeDeviceTenant(tenant string, in DeviceInput, at time.Time) {
	s.graph(tenant).observe(func(g *Graph) { g.ObserveDevice(in, at) })
}

func (s *IndexedStore) snapshotAtTenant(tenant string, at time.Time) Snapshot {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return emptySnapshot(tenant, at)
	}
	return g.inner.SnapshotAt(at)
}

func (s *IndexedStore) latestTenant(tenant string) Snapshot {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return emptySnapshot(tenant, time.Time{})
	}
	return g.inner.Latest()
}

func (s *IndexedStore) neighborsTenant(tenant, nodeID string, at time.Time) []string {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return nil
	}
	return g.neighbors(nodeID, at)
}

func (s *IndexedStore) traverseTenant(tenant, from, to string, at time.Time) []string {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return nil
	}
	return g.traverse(from, to, at)
}

var _ Store = (*IndexedStore)(nil)

// indexedGraph wraps the canonical Graph (identical temporal/upsert
// semantics — one source of truth) and maintains adjacency indexes beside it.
type indexedGraph struct {
	inner *Graph

	mu  sync.RWMutex
	fwd map[string]map[string]string // from -> to -> edgeID
	rev map[string]map[string]string // to -> from -> edgeID
}

func newIndexedGraph(tenant string) *indexedGraph {
	return &indexedGraph{
		inner: NewGraph(tenant),
		fwd:   map[string]map[string]string{},
		rev:   map[string]map[string]string{},
	}
}

// observe applies a builder mutation to the inner graph and re-indexes the
// edges it touched. Builder mutations only ADD or EXTEND edges, so indexing
// the full current edge id set per (from,to) pair stays consistent; the
// index holds ids and validity always comes from the inner graph (no second
// copy of temporal truth to drift).
func (ig *indexedGraph) observe(fn func(*Graph)) {
	fn(ig.inner)
	ig.mu.Lock()
	defer ig.mu.Unlock()
	// Reconcile: index any edge not yet present. Builder calls touch a handful
	// of edges; EdgesUnsafe iteration is bounded by the snapshot size only on
	// first build. To keep observe O(touched), Graph exposes a generation of
	// recently-upserted edge ids.
	for _, e := range ig.inner.drainRecentEdges() {
		if ig.fwd[e.From] == nil {
			ig.fwd[e.From] = map[string]string{}
		}
		ig.fwd[e.From][e.To] = e.ID
		if ig.rev[e.To] == nil {
			ig.rev[e.To] = map[string]string{}
		}
		ig.rev[e.To][e.From] = e.ID
	}
}

func (ig *indexedGraph) pruneBefore(cutoff time.Time) int {
	nodes, edges := ig.inner.PruneBefore(cutoff)
	if nodes+edges == 0 {
		return 0
	}
	ig.rebuildIndexes()
	return nodes + edges
}

func (ig *indexedGraph) rebuildIndexes() {
	ig.mu.Lock()
	defer ig.mu.Unlock()
	ig.fwd = map[string]map[string]string{}
	ig.rev = map[string]map[string]string{}
	for _, e := range ig.inner.allEdges() {
		if ig.fwd[e.From] == nil {
			ig.fwd[e.From] = map[string]string{}
		}
		ig.fwd[e.From][e.To] = e.ID
		if ig.rev[e.To] == nil {
			ig.rev[e.To] = map[string]string{}
		}
		ig.rev[e.To][e.From] = e.ID
	}
}

func (ig *indexedGraph) neighbors(nodeID string, at time.Time) []string {
	ig.mu.RLock()
	defer ig.mu.RUnlock()
	seen := map[string]bool{}
	for to, eid := range ig.fwd[nodeID] {
		if ig.inner.edgeValidAt(eid, at) {
			seen[to] = true
		}
	}
	for from, eid := range ig.rev[nodeID] {
		if ig.inner.edgeValidAt(eid, at) {
			seen[from] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (ig *indexedGraph) traverse(from, to string, at time.Time) []string {
	if from == to {
		return []string{from}
	}
	ig.mu.RLock()
	defer ig.mu.RUnlock()
	parent := map[string]string{from: from}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		next := make([]string, 0, len(ig.fwd[cur]))
		for n, eid := range ig.fwd[cur] {
			if ig.inner.edgeValidAt(eid, at) {
				next = append(next, n)
			}
		}
		sort.Strings(next) // deterministic routes
		for _, n := range next {
			if _, ok := parent[n]; ok {
				continue
			}
			parent[n] = cur
			if n == to {
				return rebuild(parent, from, to)
			}
			queue = append(queue, n)
		}
	}
	return nil
}
