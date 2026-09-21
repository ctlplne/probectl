// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"context"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const topologyWriteFenceTimeout = 5 * time.Second

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

type lifecycleStore interface {
	Store
	DeleteTenant(string) int
	PruneTenantBefore(string, time.Time) int
}

type lifecycleWriteFencedStore struct {
	*writeFencedStore
	nextLifecycle lifecycleStore
}

// WithTenantWriteFence guards every tenant-bound topology mutation with the
// deployment-wide lifecycle lease. The topology contract has void mutation
// methods, so a fenced or unavailable lease fails closed by leaving the graph
// unchanged. Reads, retention, and erasure continue through the original store.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	if HasTenantWriteFence(next) {
		return next
	}
	wrapped := &writeFencedStore{next: next, fence: fence}
	if lifecycle, ok := next.(lifecycleStore); ok {
		return &lifecycleWriteFencedStore{
			writeFencedStore: wrapped,
			nextLifecycle:    lifecycle,
		}
	}
	return wrapped
}

func (s *writeFencedStore) ForTenant(tenant string) (TenantStore, error) {
	next, err := s.next.ForTenant(tenant)
	if err != nil {
		return nil, err
	}
	return &writeFencedTenantStore{
		tenant: tenant,
		next:   next,
		fence:  s.fence,
	}, nil
}

func (s *lifecycleWriteFencedStore) DeleteTenant(tenant string) int {
	return s.nextLifecycle.DeleteTenant(tenant)
}

func (s *lifecycleWriteFencedStore) PruneTenantBefore(tenant string, cutoff time.Time) int {
	return s.nextLifecycle.PruneTenantBefore(tenant, cutoff)
}

type writeFencedTenantStore struct {
	tenant string
	next   TenantStore
	fence  tenancy.WriterFence
}

// mutate runs one graph mutation through the shared fence adapter. DECLARED
// DIVERGENCE from the house error semantics (S-a9f9db46): the TenantStore
// contract has VOID mutation methods (observations are fire-and-forget from
// hot ingest paths), so a fenced, failing, or absent lease cannot surface an
// error to the caller — the write is DROPPED, fail closed, and the drop is
// LOUD: logged at error level with the tenant and cause, never silent.
func (s *writeFencedTenantStore) mutate(write func()) {
	ctx, cancel := context.WithTimeout(context.Background(), topologyWriteFenceTimeout)
	defer cancel()
	err := tenancy.FencedTenantWrite(ctx, s.fence, s.tenant, tenancy.ErrWriterFenceUnavailable,
		func(context.Context) error {
			write()
			return nil
		})
	if err != nil {
		slog.Default().Error("topology mutation dropped: tenant writer fence refused the write (fail closed)",
			"tenant_id", s.tenant, "error", err.Error())
	}
}

// BatchWriter is implemented by tenant stores that can apply many
// observations under one write fence (DPR-106). The eBPF plane delivers a
// cumulative service-map snapshot with every flush — hundreds of edges — and
// fencing each edge in its own provider-role transaction cost the topology
// consumer seconds per record on the lab, so it fell behind the bus for good.
type BatchWriter interface {
	// Batch runs write against the unfenced tenant store inside ONE fence
	// check: the lease is taken once, the tenant's status is read once, and
	// every observation in write lands or the whole batch is dropped loudly.
	Batch(write func(TenantStore))
}

// Batch implements BatchWriter: one fence round trip for the whole batch.
func (s *writeFencedTenantStore) Batch(write func(TenantStore)) {
	s.mutate(func() { write(s.next) })
}

// ObserveBatched applies write through the store's BatchWriter when it has
// one, or directly otherwise (unfenced stores need no batching).
func ObserveBatched(store TenantStore, write func(TenantStore)) {
	if bw, ok := store.(BatchWriter); ok {
		bw.Batch(write)
		return
	}
	write(store)
}

func (s *writeFencedTenantStore) ObservePath(in PathInput, at time.Time) {
	s.mutate(func() { s.next.ObservePath(in, at) })
}

func (s *writeFencedTenantStore) ObserveServiceEdge(in ServiceEdgeInput, at time.Time) {
	s.mutate(func() { s.next.ObserveServiceEdge(in, at) })
}

func (s *writeFencedTenantStore) ObserveRouting(in RoutingInput, at time.Time) {
	s.mutate(func() { s.next.ObserveRouting(in, at) })
}

func (s *writeFencedTenantStore) ObserveDevice(in DeviceInput, at time.Time) {
	s.mutate(func() { s.next.ObserveDevice(in, at) })
}

func (s *writeFencedTenantStore) ObservePhysicalAdjacency(in PhysicalAdjacencyInput, at time.Time) {
	s.mutate(func() { s.next.ObservePhysicalAdjacency(in, at) })
}

func (s *writeFencedTenantStore) ReplacePhysicalAdjacencies(in PhysicalAdjacencySnapshot, at time.Time) {
	s.mutate(func() { s.next.ReplacePhysicalAdjacencies(in, at) })
}

func (s *writeFencedTenantStore) IdentityConflicts() IdentityConflictSnapshot {
	return s.next.IdentityConflicts()
}

func (s *writeFencedTenantStore) SnapshotAt(at time.Time) Snapshot {
	return s.next.SnapshotAt(at)
}

func (s *writeFencedTenantStore) Latest() Snapshot {
	return s.next.Latest()
}

func (s *writeFencedTenantStore) Neighbors(nodeID string, at time.Time) []string {
	return s.next.Neighbors(nodeID, at)
}

func (s *writeFencedTenantStore) Traverse(from, to string, at time.Time) []string {
	return s.next.Traverse(from, to, at)
}

// HasTenantWriteFence reports whether topology mutations are protected by the
// durable lifecycle writer lease.
func HasTenantWriteFence(store Store) bool {
	switch store.(type) {
	case *writeFencedStore, *lifecycleWriteFencedStore:
		return true
	default:
		return false
	}
}
