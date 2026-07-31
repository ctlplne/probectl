// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otelstore

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

// WithTenantWriteFence wraps both OTLP mutation seams with the durable
// deployment-wide erasure barrier. Queries and lifecycle operations continue
// through the original store unchanged.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	return &writeFencedStore{next: next, fence: fence}
}

func (s *writeFencedStore) WriteSpans(
	ctx context.Context,
	spans []Span,
) error {
	if len(spans) == 0 {
		return s.next.WriteSpans(ctx, spans)
	}
	tenantIDs := make([]string, 0, len(spans))
	for i := range spans {
		if spans[i].TenantID == "" {
			return ErrNoTenant
		}
		tenantIDs = append(tenantIDs, spans[i].TenantID)
	}
	return s.fence.WithTenantWrites(
		ctx,
		tenantIDs,
		func(ctx context.Context) error {
			return s.next.WriteSpans(ctx, spans)
		},
	)
}

func (s *writeFencedStore) WriteLogs(
	ctx context.Context,
	recs []LogRecord,
) error {
	if len(recs) == 0 {
		return s.next.WriteLogs(ctx, recs)
	}
	tenantIDs := make([]string, 0, len(recs))
	for i := range recs {
		if recs[i].TenantID == "" {
			return ErrNoTenant
		}
		tenantIDs = append(tenantIDs, recs[i].TenantID)
	}
	return s.fence.WithTenantWrites(
		ctx,
		tenantIDs,
		func(ctx context.Context) error {
			return s.next.WriteLogs(ctx, recs)
		},
	)
}

func (s *writeFencedStore) QuerySpans(
	ctx context.Context,
	tenantID string,
	q SpanQuery,
) ([]Span, error) {
	return s.next.QuerySpans(ctx, tenantID, q)
}

func (s *writeFencedStore) QueryLogs(
	ctx context.Context,
	tenantID string,
	q LogQuery,
) ([]LogRecord, error) {
	return s.next.QueryLogs(ctx, tenantID, q)
}

func (s *writeFencedStore) Close() error {
	return s.next.Close()
}

// ClickHouseStore returns the concrete backend through the writer-fence
// decorator. The edition seam uses it only to install per-tenant silo routing;
// OTLP writes still enter through the decorated Store.
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
// ingest-only writer-fence decorator. Tenant lifecycle uses it to discover
// optional erasure, subject-export, and retention capabilities.
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

// HasTenantWriteFence reports whether OTLP writes are protected by the durable
// lifecycle writer lease. It is used by the runtime wiring regression.
func HasTenantWriteFence(store Store) bool {
	_, ok := store.(*writeFencedStore)
	return ok
}
