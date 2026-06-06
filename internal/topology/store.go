package topology

import (
	"sync"
	"time"
)

// Store manages per-tenant topology graphs. It is the query API the AI semantic
// layer (S23) wraps with tenant-then-RBAC scoping, and the adjacency contract the
// dedicated-engine migration (S43) implements. Every method is tenant-scoped: the
// store never returns another tenant's graph (CLAUDE.md §7 guardrail 1).
type Store interface {
	ObservePath(tenant string, in PathInput, at time.Time)
	ObserveServiceEdge(tenant string, in ServiceEdgeInput, at time.Time)
	ObserveRouting(tenant string, in RoutingInput, at time.Time)
	ObserveDevice(tenant string, in DeviceInput, at time.Time)

	SnapshotAt(tenant string, at time.Time) Snapshot
	Latest(tenant string) Snapshot
	Neighbors(tenant, nodeID string, at time.Time) []string
	Traverse(tenant, from, to string, at time.Time) []string
}

// MemoryStore is the in-memory Store: one Graph per tenant. The
// Postgres/ClickHouse adjacency backing (and the S43 dedicated engine) implement
// the same interface.
type MemoryStore struct {
	mu     sync.Mutex
	graphs map[string]*Graph
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{graphs: map[string]*Graph{}} }

// DeleteTenant drops the tenant's entire topology graph (every snapshot/
// version — S-T5 verifiable erasure, U-027) and reports whether one existed.
func (s *MemoryStore) DeleteTenant(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.graphs[tenant]; !ok {
		return 0
	}
	delete(s.graphs, tenant)
	return 1
}

func (s *MemoryStore) graph(tenant string) *Graph {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.graphs[tenant]
	if !ok {
		g = NewGraph(tenant)
		s.graphs[tenant] = g
	}
	return g
}

// ObservePath implements Store.
func (s *MemoryStore) ObservePath(tenant string, in PathInput, at time.Time) {
	s.graph(tenant).ObservePath(in, at)
}

// ObserveServiceEdge implements Store.
func (s *MemoryStore) ObserveServiceEdge(tenant string, in ServiceEdgeInput, at time.Time) {
	s.graph(tenant).ObserveServiceEdge(in, at)
}

// ObserveRouting implements Store.
func (s *MemoryStore) ObserveRouting(tenant string, in RoutingInput, at time.Time) {
	s.graph(tenant).ObserveRouting(in, at)
}

// ObserveDevice implements Store.
func (s *MemoryStore) ObserveDevice(tenant string, in DeviceInput, at time.Time) {
	s.graph(tenant).ObserveDevice(in, at)
}

// SnapshotAt implements Store.
func (s *MemoryStore) SnapshotAt(tenant string, at time.Time) Snapshot {
	return s.graph(tenant).SnapshotAt(at)
}

// Latest implements Store.
func (s *MemoryStore) Latest(tenant string) Snapshot { return s.graph(tenant).Latest() }

// Neighbors implements Store.
func (s *MemoryStore) Neighbors(tenant, nodeID string, at time.Time) []string {
	return s.graph(tenant).Neighbors(nodeID, at)
}

// Traverse implements Store.
func (s *MemoryStore) Traverse(tenant, from, to string, at time.Time) []string {
	return s.graph(tenant).Traverse(from, to, at)
}

var _ Store = (*MemoryStore)(nil)
