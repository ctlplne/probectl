// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

// WithTenantWriteFence guards the actual path backend mutation. When the
// existing write-behind batching wrapper is present, its inner backend is
// decorated so the shared lease spans the real Save/SaveBatch call rather than
// only the enqueue operation.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	if batching, ok := next.(*BatchingSaver); ok {
		batching.inner = WithTenantWriteFence(batching.inner, fence)
		return batching
	}
	return &writeFencedStore{next: next, fence: fence}
}

func (s *writeFencedStore) Save(
	ctx context.Context,
	tenantID string,
	p *path.Path,
) error {
	return tenancy.FencedTenantWrite(ctx, s.fence, tenantID, ErrNoTenant,
		func(ctx context.Context) error { return s.next.Save(ctx, tenantID, p) })
}

// SaveBatch preserves the ClickHouse cross-path batching fast path while
// acquiring all involved tenant leases in canonical order before any row is
// written. Mixed active/fenced batches therefore fail before the backend.
func (s *writeFencedStore) SaveBatch(
	ctx context.Context,
	items []PathItem,
) error {
	if len(items) == 0 {
		return nil
	}
	return tenancy.FencedWrite(ctx, s.fence, items,
		func(it PathItem) string { return it.TenantID }, ErrNoTenant,
		func(ctx context.Context) error {
			if batch, ok := s.next.(batchSaver); ok {
				return batch.SaveBatch(ctx, items)
			}
			for i := range items {
				if err := s.next.Save(
					ctx,
					items[i].TenantID,
					items[i].P,
				); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (s *writeFencedStore) Latest(
	ctx context.Context,
	tenantID string,
	target string,
) (*path.Path, bool, error) {
	return s.next.Latest(ctx, tenantID, target)
}

func (s *writeFencedStore) History(
	ctx context.Context,
	tenantID string,
	target string,
	q HistoryQuery,
) ([]Snapshot, error) {
	return s.next.History(ctx, tenantID, target, q)
}

func (s *writeFencedStore) Close() error {
	return s.next.Close()
}

// UnderlyingStore returns the concrete backend for lifecycle capability
// discovery through batching and writer-fence decorators.
func UnderlyingStore(store Store) Store {
	for {
		switch current := store.(type) {
		case *BatchingSaver:
			store = current.inner
		case *writeFencedStore:
			store = current.next
		default:
			return store
		}
	}
}

// HasTenantWriteFence reports whether the actual backend Save/SaveBatch seam is
// protected by the durable lifecycle writer lease.
func HasTenantWriteFence(store Store) bool {
	for {
		switch current := store.(type) {
		case *BatchingSaver:
			store = current.inner
		case *writeFencedStore:
			return true
		default:
			return false
		}
	}
}
