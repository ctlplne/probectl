// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"context"
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

func (s *writeFencedTenantStore) mutate(write func()) {
	if s.fence == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), topologyWriteFenceTimeout)
	defer cancel()
	_ = s.fence.WithTenantWrites(
		ctx,
		[]string{s.tenant},
		func(context.Context) error {
			write()
			return nil
		},
	)
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
