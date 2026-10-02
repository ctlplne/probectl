// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

// SaveBatchPartitioned fences a COALESCED multi-tenant flush per tenant: it
// persists every eligible tenant's paths and returns a map of exactly the
// tenants whose paths were rejected (keyed by tenant_id), so the write-behind
// batcher drops only the fenced tenants' paths and stores the rest. One
// tenant's lifecycle state never decides another tenant's write
// (docs/guardrails.md G7-1). A non-nil error is a batch-wide failure (an
// unverifiable fence or a backend failure for the eligible paths), never a
// co-batched tenant being fenced.
func (s *writeFencedStore) SaveBatchPartitioned(
	ctx context.Context,
	items []PathItem,
) (map[string]error, error) {
	if len(items) == 0 {
		return nil, nil
	}
	return tenancy.PartitionedFencedWrite(ctx, s.fence, items,
		func(it PathItem) string { return it.TenantID }, ErrNoTenant,
		func(ctx context.Context, eligible []PathItem) error {
			if len(eligible) == 0 {
				return nil
			}
			if batch, ok := s.next.(batchSaver); ok {
				return batch.SaveBatch(ctx, eligible)
			}
			for i := range eligible {
				if err := s.next.Save(
					ctx,
					eligible[i].TenantID,
					eligible[i].P,
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
