// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flowstore

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type writeFencedStore struct {
	next  Store
	fence tenancy.WriterFence
}

type subjectDeletingStore interface {
	DeleteSubject(
		context.Context,
		string,
		string,
	) (deleted, remaining int64, err error)
}

type subjectDeletingWriteFencedStore struct {
	*writeFencedStore
	deleter subjectDeletingStore
}

// WithTenantWriteFence wraps the flow mutation seam with the durable
// deployment-wide erasure barrier. Reads, retention, export, deletion, and
// backend routing continue through the original store unchanged.
func WithTenantWriteFence(next Store, fence tenancy.WriterFence) Store {
	store := &writeFencedStore{next: next, fence: fence}
	if deleter, ok := next.(subjectDeletingStore); ok {
		return &subjectDeletingWriteFencedStore{
			writeFencedStore: store,
			deleter:          deleter,
		}
	}
	return store
}

func (s *writeFencedStore) Insert(ctx context.Context, rows []Row) error {
	if len(rows) == 0 {
		return s.next.Insert(ctx, rows)
	}
	if err := validateInsertRows(rows); err != nil {
		return err
	}
	tenantIDs := make([]string, 0, len(rows))
	for i := range rows {
		tenantIDs = append(tenantIDs, rows[i].TenantID)
	}
	return s.fence.WithTenantWrites(
		ctx,
		tenantIDs,
		func(ctx context.Context) error {
			return s.next.Insert(ctx, rows)
		},
	)
}

func (s *writeFencedStore) TopTalkers(
	ctx context.Context,
	q TopQuery,
) ([]TopRow, error) {
	return s.next.TopTalkers(ctx, q)
}

func (s *writeFencedStore) TopSeries(
	ctx context.Context,
	q TopQuery,
	top []TopRow,
) ([]SeriesPoint, error) {
	return s.next.TopSeries(ctx, q, top)
}

func (s *writeFencedStore) Capacity(
	ctx context.Context,
	q CapacityQuery,
) ([]CapacityPoint, error) {
	return s.next.Capacity(ctx, q)
}

func (s *writeFencedStore) Anomalies(
	ctx context.Context,
	q AnomalyQuery,
) ([]Anomaly, error) {
	return s.next.Anomalies(ctx, q)
}

func (s *writeFencedStore) DeleteTenant(
	ctx context.Context,
	tenantID string,
) (int64, error) {
	return s.next.DeleteTenant(ctx, tenantID)
}

func (s *writeFencedStore) DeleteTenantBefore(
	ctx context.Context,
	tenantID string,
	cutoff time.Time,
) error {
	return s.next.DeleteTenantBefore(ctx, tenantID, cutoff)
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

// DeleteSubject preserves the underlying store's optional subject-erasure
// capability. WithTenantWriteFence returns this wrapper only when the concrete
// backend implements that capability, so an incapable backend is not falsely
// advertised to the tenant-lifecycle engine.
func (s *subjectDeletingWriteFencedStore) DeleteSubject(
	ctx context.Context,
	tenantID string,
	subject string,
) (deleted, remaining int64, err error) {
	return s.deleter.DeleteSubject(ctx, tenantID, subject)
}

// ClickHouseStore returns the concrete backend through the writer-fence
// decorator. The edition seam uses it only to install per-tenant silo routing;
// flow writes still enter through the decorated Store.
func ClickHouseStore(store Store) (*ClickHouse, bool) {
	for {
		switch current := store.(type) {
		case *ClickHouse:
			return current, true
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			return nil, false
		}
	}
}

// HasTenantWriteFence reports whether Store.Insert is protected by the durable
// lifecycle writer lease. It is used by the runtime wiring regression.
func HasTenantWriteFence(store Store) bool {
	switch store.(type) {
	case *writeFencedStore, *subjectDeletingWriteFencedStore:
		return true
	default:
		return false
	}
}
