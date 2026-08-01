// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpfstore

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

// WithTenantWriteFence wraps the eBPF aggregate mutation seam with the durable
// deployment-wide erasure barrier. Queries, deletion, and backend routing
// continue through the original store unchanged.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	return &writeFencedStore{next: next, fence: fence}
}

func (s *writeFencedStore) Insert(ctx context.Context, edges []Edge) error {
	return tenancy.FencedWrite(ctx, s.fence, edges,
		func(e Edge) string { return e.TenantID }, ErrNoTenant,
		func(ctx context.Context) error { return s.next.Insert(ctx, edges) })
}

func (s *writeFencedStore) TopEdges(
	ctx context.Context,
	tenantID string,
	q EdgeQuery,
) ([]Edge, error) {
	return s.next.TopEdges(ctx, tenantID, q)
}

func (s *writeFencedStore) DeleteTenant(
	ctx context.Context,
	tenantID string,
) (int64, error) {
	return s.next.DeleteTenant(ctx, tenantID)
}

func (s *writeFencedStore) Close() error {
	return s.next.Close()
}

// ClickHouseStore returns the concrete backend through the writer-fence
// decorator. The edition seam uses it only to install per-tenant silo routing;
// eBPF writes still enter through the decorated Store.
func ClickHouseStore(store Store) (*ClickHouse, bool) {
	for {
		switch current := store.(type) {
		case *ClickHouse:
			return current, true
		case *writeFencedStore:
			store = current.next
		default:
			return nil, false
		}
	}
}

// UnderlyingStore returns the concrete lifecycle backend through the
// ingest-only writer-fence decorator. Tenant lifecycle uses the concrete
// backend to discover optional subject-export, subject-erasure, and retention
// capabilities; production ingest and API paths must retain the decorated
// Store.
func UnderlyingStore(store Store) Store {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		default:
			return store
		}
	}
}

// HasTenantWriteFence reports whether Store.Insert is protected by the durable
// lifecycle writer lease. It is used by the runtime wiring regression.
func HasTenantWriteFence(store Store) bool {
	_, ok := store.(*writeFencedStore)
	return ok
}
