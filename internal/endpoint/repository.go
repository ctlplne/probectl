// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/store/endpointstore"
)

// Repository combines the durable event store with the bounded latest-state
// snapshot. Live bus observations update the cache; the first read for a
// tenant after restart loads that tenant's latest rows from durable storage.
type Repository struct {
	durable endpointstore.Store
	cache   *SnapshotStore

	mu     sync.Mutex
	loaded map[string]bool
}

// NewRepository builds a read-through endpoint repository.
func NewRepository(durable endpointstore.Store, cache *SnapshotStore) *Repository {
	if cache == nil {
		cache = NewSnapshotStore(0)
	}
	return &Repository{durable: durable, cache: cache, loaded: map[string]bool{}}
}

// Persist stores one event before the durable consumer commits its bus offset.
func (r *Repository) Persist(ctx context.Context, tenant, agent string, view ResultView) error {
	if r == nil || r.durable == nil {
		return errors.New("endpoint: durable event store is unavailable")
	}
	return r.durable.Insert(ctx, []endpointstore.Event{toStoredEvent(tenant, agent, view)})
}

// RecordCache updates the bounded per-replica view. It is deliberately separate
// from Persist so the shared durable consumer and per-replica view consumer do
// not multiply ClickHouse writes.
func (r *Repository) RecordCache(tenant, agent string, view ResultView) {
	if r == nil {
		return
	}
	r.cache.Record(tenant, agent, view)
}

// ListFilteredContext loads this tenant's durable latest rows once after
// restart, then reads the bounded cache. No unscoped durable query exists.
func (r *Repository) ListFilteredContext(ctx context.Context, tenant string, filter ListFilter) ([]View, error) {
	if tenant == "" {
		return nil, endpointstore.ErrNoTenant
	}
	if err := r.ensureLoaded(ctx, tenant); err != nil {
		return nil, err
	}
	return r.cache.ListFiltered(tenant, filter)
}

func (r *Repository) ensureLoaded(ctx context.Context, tenant string) error {
	if tenant == "" || r == nil || r.durable == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded[tenant] {
		return nil
	}
	events, err := r.durable.Latest(ctx, tenant)
	if err != nil {
		return err
	}
	for _, event := range events {
		if event.TenantID != tenant {
			continue // defense in depth; durable implementations also reject this.
		}
		r.cache.Record(tenant, event.AgentID, fromStoredEvent(event))
	}
	r.loaded[tenant] = true
	return nil
}

func toStoredEvent(tenant, agent string, view ResultView) endpointstore.Event {
	key := ""
	if view.Type == TypeSession {
		key = view.Target
	}
	return endpointstore.Event{
		TenantID: tenant, AgentID: agent, Type: view.Type, SignalKey: key,
		Target: view.Target, Success: view.Success, Error: view.Error,
		Metrics: view.Metrics, Attributes: view.Attributes, ObservedAt: view.ObservedAt,
	}
}

func fromStoredEvent(event endpointstore.Event) ResultView {
	return ResultView{
		Type: event.Type, Target: event.Target, Success: event.Success, Error: event.Error,
		Metrics: event.Metrics, Attributes: event.Attributes, ObservedAt: event.ObservedAt,
	}
}

// PruneTenantBefore prunes the per-replica read cache. Durable history pruning
// is attached separately to tenant lifecycle with its context-aware store seam.
func (r *Repository) PruneTenantBefore(tenant string, cutoff time.Time) int {
	if r == nil {
		return 0
	}
	return r.cache.PruneTenantBefore(tenant, cutoff)
}

// ExportSubject streams the tenant's durable events about the subject (ING-15).
// The durable store is the cross-replica source of truth that a restart rebuilds
// the per-replica cache from, so the portability bundle reads from it rather than
// from one replica's bounded view.
func (r *Repository) ExportSubject(tenant, subject string, w io.Writer) (int64, error) {
	if r == nil || r.durable == nil {
		return 0, errors.New("endpoint: durable event store is unavailable")
	}
	return r.durable.ExportSubject(context.Background(), tenant, subject, w)
}

// DeleteSubject erases the subject from the DURABLE event store across replicas
// and from this replica's derived cache (ING-15). Before the fix only the cache
// was cleared, so the subject reappeared on the next ensureLoaded/restart and on
// every other replica while the receipt still reported "complete" — a false
// attestation. The durable store is the source of truth for the verified-zero
// count: a nil durable store or a durable error fails closed (remaining > 0) so
// the plane is never reported complete without a durable delete.
func (r *Repository) DeleteSubject(tenant, subject string) (deleted, remaining int64) {
	if r == nil || r.durable == nil {
		return 0, 1 // no durable delete happened: never attest verified-zero.
	}
	// Clear this replica's bounded cache so it does not keep serving the subject
	// until its next reload; the cache is already loaded for served tenants.
	if err := r.ensureLoaded(context.Background(), tenant); err == nil {
		r.cache.DeleteSubject(tenant, subject)
	}
	durableDeleted, durableRemaining, err := r.durable.DeleteSubject(context.Background(), tenant, subject)
	if err != nil {
		return 0, 1 // fail closed: never attest verified-zero after a durable error.
	}
	return durableDeleted, durableRemaining
}
