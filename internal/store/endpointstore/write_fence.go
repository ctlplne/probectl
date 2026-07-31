// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpointstore

import (
	"context"
	"io"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

// WithTenantWriteFence wraps the endpoint mutation seam with the durable
// deployment-wide erasure barrier. Reads, retention, export, deletion, and
// backend routing continue through the original store unchanged.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	return &writeFencedStore{next: next, fence: fence}
}

func (s *writeFencedStore) Insert(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return s.next.Insert(ctx, events)
	}
	if err := validate(events); err != nil {
		return err
	}
	tenantIDs := make([]string, 0, len(events))
	for i := range events {
		tenantIDs = append(tenantIDs, events[i].TenantID)
	}
	return s.fence.WithTenantWrites(
		ctx,
		tenantIDs,
		func(ctx context.Context) error {
			return s.next.Insert(ctx, events)
		},
	)
}

func (s *writeFencedStore) Latest(
	ctx context.Context,
	tenantID string,
) ([]Event, error) {
	return s.next.Latest(ctx, tenantID)
}

func (s *writeFencedStore) PruneTenantBefore(
	ctx context.Context,
	tenantID string,
	cutoff time.Time,
) (int, error) {
	return s.next.PruneTenantBefore(ctx, tenantID, cutoff)
}

func (s *writeFencedStore) DeleteTenant(
	ctx context.Context,
	tenantID string,
) (int64, error) {
	return s.next.DeleteTenant(ctx, tenantID)
}

func (s *writeFencedStore) ExportTenant(
	ctx context.Context,
	tenantID string,
	w io.Writer,
) (int64, error) {
	return s.next.ExportTenant(ctx, tenantID, w)
}

func (s *writeFencedStore) Close() error {
	return s.next.Close()
}

// ClickHouseStore returns the concrete backend through the writer-fence
// decorator. The edition seam uses it only to install per-tenant silo routing;
// endpoint writes still enter through the decorated Store.
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

// HasTenantWriteFence reports whether Store.Insert is protected by the durable
// lifecycle writer lease. It is used by the runtime wiring regression.
func HasTenantWriteFence(store Store) bool {
	_, ok := store.(*writeFencedStore)
	return ok
}
