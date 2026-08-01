// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// ExportSubject ensures restart-loaded state before applying the existing
// subject filter to the tenant's latest view.
func (r *Repository) ExportSubject(tenant, subject string, w io.Writer) (int64, error) {
	if err := r.ensureLoaded(context.Background(), tenant); err != nil {
		return 0, err
	}
	return r.cache.ExportSubject(tenant, subject, w)
}

// DeleteSubject removes subject labels from this replica's derived view. The
// raw durable event history follows the plane retention/tenant-erasure policy.
func (r *Repository) DeleteSubject(tenant, subject string) (deleted, remaining int64) {
	if err := r.ensureLoaded(context.Background(), tenant); err != nil {
		return 0, 1 // fail closed: never attest verified-zero after a load error.
	}
	return r.cache.DeleteSubject(tenant, subject)
}
