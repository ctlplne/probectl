// SPDX-License-Identifier: LicenseRef-probectl-TBD

package topology

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrNoTenant is returned when a topology operation is attempted without an
// already-authenticated tenant scope.
var ErrNoTenant = errors.New("topology: tenant_id is required")

// Store manages per-tenant topology graphs. It is the query API the AI semantic
// layer (S23) wraps with tenant-then-RBAC scoping, and the adjacency contract the
// dedicated-engine migration (S43) implements. Tenant-owned callers first bind a
// tenant via ForTenant; the returned TenantStore does not accept tenant strings,
// so reads and writes cannot accidentally swap tenants after authentication.
type Store interface {
	ForTenant(tenant string) (TenantStore, error)
}

// TenantStore is a topology graph already bound to one tenant. Public methods
// accept graph-relative node/edge data only; the tenant namespace lives in this
// handle, not in each caller-controlled method argument.
type TenantStore interface {
	ObservePath(in PathInput, at time.Time)
	ObserveServiceEdge(in ServiceEdgeInput, at time.Time)
	ObserveRouting(in RoutingInput, at time.Time)
	ObserveDevice(in DeviceInput, at time.Time)

	SnapshotAt(at time.Time) Snapshot
	Latest() Snapshot
	Neighbors(nodeID string, at time.Time) []string
	Traverse(from, to string, at time.Time) []string
}

type tenantBackend interface {
	observePathTenant(tenant string, in PathInput, at time.Time)
	observeServiceEdgeTenant(tenant string, in ServiceEdgeInput, at time.Time)
	observeRoutingTenant(tenant string, in RoutingInput, at time.Time)
	observeDeviceTenant(tenant string, in DeviceInput, at time.Time)
	snapshotAtTenant(tenant string, at time.Time) Snapshot
	latestTenant(tenant string) Snapshot
	neighborsTenant(tenant, nodeID string, at time.Time) []string
	traverseTenant(tenant, from, to string, at time.Time) []string
}

type tenantStore struct {
	tenant string
	store  tenantBackend
}

func bindTenant(store tenantBackend, tenant string) (TenantStore, error) {
	tenant, err := normalizeTenant(tenant)
	if err != nil {
		return nil, err
	}
	return tenantStore{tenant: tenant, store: store}, nil
}

func normalizeTenant(tenant string) (string, error) {
	if strings.TrimSpace(tenant) == "" {
		return "", ErrNoTenant
	}
	if tenant != strings.TrimSpace(tenant) || strings.ContainsAny(tenant, "\x00/\\") || tenant == "." || tenant == ".." {
		return "", fmt.Errorf("topology: invalid tenant_id %q", tenant)
	}
	return tenant, nil
}

func emptySnapshot(tenant string, at time.Time) Snapshot {
	return Snapshot{Tenant: tenant, At: at}
}

// ObservePath implements TenantStore.
func (t tenantStore) ObservePath(in PathInput, at time.Time) {
	t.store.observePathTenant(t.tenant, in, at)
}

// ObserveServiceEdge implements TenantStore.
func (t tenantStore) ObserveServiceEdge(in ServiceEdgeInput, at time.Time) {
	t.store.observeServiceEdgeTenant(t.tenant, in, at)
}

// ObserveRouting implements TenantStore.
func (t tenantStore) ObserveRouting(in RoutingInput, at time.Time) {
	t.store.observeRoutingTenant(t.tenant, in, at)
}

// ObserveDevice implements TenantStore.
func (t tenantStore) ObserveDevice(in DeviceInput, at time.Time) {
	t.store.observeDeviceTenant(t.tenant, in, at)
}

// SnapshotAt implements TenantStore.
func (t tenantStore) SnapshotAt(at time.Time) Snapshot {
	return t.store.snapshotAtTenant(t.tenant, at)
}

// Latest implements TenantStore.
func (t tenantStore) Latest() Snapshot {
	return t.store.latestTenant(t.tenant)
}

// Neighbors implements TenantStore.
func (t tenantStore) Neighbors(nodeID string, at time.Time) []string {
	return t.store.neighborsTenant(t.tenant, nodeID, at)
}

// Traverse implements TenantStore.
func (t tenantStore) Traverse(from, to string, at time.Time) []string {
	return t.store.traverseTenant(t.tenant, from, to, at)
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

// ForTenant returns a graph handle bound to one tenant.
func (s *MemoryStore) ForTenant(tenant string) (TenantStore, error) {
	return bindTenant(s, tenant)
}

// DeleteTenant drops the tenant's entire topology graph (every snapshot/
// version — S-T5 verifiable erasure, U-027) and reports whether one existed.
func (s *MemoryStore) DeleteTenant(tenant string) int {
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

func (s *MemoryStore) graphIfExists(tenant string) (*Graph, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.graphs[tenant]
	return g, ok
}

// ObservePath is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant and call TenantStore.ObservePath instead.
func (s *MemoryStore) ObservePath(tenant string, in PathInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observePathTenant(tenant, in, at)
}

// ObserveServiceEdge is a concrete compatibility helper. Tenant-owned
// production callers should bind ForTenant first.
func (s *MemoryStore) ObserveServiceEdge(tenant string, in ServiceEdgeInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeServiceEdgeTenant(tenant, in, at)
}

// ObserveRouting is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *MemoryStore) ObserveRouting(tenant string, in RoutingInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeRoutingTenant(tenant, in, at)
}

// ObserveDevice is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *MemoryStore) ObserveDevice(tenant string, in DeviceInput, at time.Time) {
	if _, err := normalizeTenant(tenant); err != nil {
		return
	}
	s.observeDeviceTenant(tenant, in, at)
}

// SnapshotAt is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *MemoryStore) SnapshotAt(tenant string, at time.Time) Snapshot {
	if _, err := normalizeTenant(tenant); err != nil {
		return Snapshot{At: at}
	}
	return s.snapshotAtTenant(tenant, at)
}

// Latest is a concrete compatibility helper. Tenant-owned production callers
// should bind ForTenant first.
func (s *MemoryStore) Latest(tenant string) Snapshot {
	if _, err := normalizeTenant(tenant); err != nil {
		return Snapshot{}
	}
	return s.latestTenant(tenant)
}

// Neighbors is a concrete compatibility helper. Tenant-owned production
// callers should bind ForTenant first.
func (s *MemoryStore) Neighbors(tenant, nodeID string, at time.Time) []string {
	if _, err := normalizeTenant(tenant); err != nil {
		return nil
	}
	return s.neighborsTenant(tenant, nodeID, at)
}

// Traverse is a concrete compatibility helper. Tenant-owned production callers
// should bind ForTenant first.
func (s *MemoryStore) Traverse(tenant, from, to string, at time.Time) []string {
	if _, err := normalizeTenant(tenant); err != nil {
		return nil
	}
	return s.traverseTenant(tenant, from, to, at)
}

func (s *MemoryStore) observePathTenant(tenant string, in PathInput, at time.Time) {
	s.graph(tenant).ObservePath(in, at)
}

func (s *MemoryStore) observeServiceEdgeTenant(tenant string, in ServiceEdgeInput, at time.Time) {
	s.graph(tenant).ObserveServiceEdge(in, at)
}

func (s *MemoryStore) observeRoutingTenant(tenant string, in RoutingInput, at time.Time) {
	s.graph(tenant).ObserveRouting(in, at)
}

func (s *MemoryStore) observeDeviceTenant(tenant string, in DeviceInput, at time.Time) {
	s.graph(tenant).ObserveDevice(in, at)
}

func (s *MemoryStore) snapshotAtTenant(tenant string, at time.Time) Snapshot {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return emptySnapshot(tenant, at)
	}
	return g.SnapshotAt(at)
}

func (s *MemoryStore) latestTenant(tenant string) Snapshot {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return emptySnapshot(tenant, time.Time{})
	}
	return g.Latest()
}

func (s *MemoryStore) neighborsTenant(tenant, nodeID string, at time.Time) []string {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return nil
	}
	return g.Neighbors(nodeID, at)
}

func (s *MemoryStore) traverseTenant(tenant, from, to string, at time.Time) []string {
	g, ok := s.graphIfExists(tenant)
	if !ok {
		return nil
	}
	return g.Traverse(from, to, at)
}

var _ Store = (*MemoryStore)(nil)
