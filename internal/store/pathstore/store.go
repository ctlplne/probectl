// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/path"
)

// ErrNoTenant refuses any tenant-owned path operation without an outer tenant
// scope. Stores return no data rather than falling back to an unscoped query.
var ErrNoTenant = errors.New("pathstore: tenant_id is required (refusing an unscoped query)")

// Snapshot is one immutable path-discovery round. ID is random and opaque; it
// is never sufficient authorization because every read is also constrained by
// tenant_id and target in the store.
type Snapshot struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Path       path.Path `json:"path"`
}

// HistoryQuery bounds a snapshot read. IDs are used by stable shared views;
// when present they select only those exact rounds and supersede the time range.
type HistoryQuery struct {
	From  time.Time
	To    time.Time
	Limit int
	IDs   []string
}

// Store persists and serves discovered Paths, tenant-scoped.
type Store interface {
	Save(ctx context.Context, tenantID string, p *path.Path) error
	// Latest returns the most recently saved path to target for a tenant.
	Latest(ctx context.Context, tenantID, target string) (*path.Path, bool, error)
	// History returns newest-first immutable rounds for exactly one tenant and target.
	History(ctx context.Context, tenantID, target string, q HistoryQuery) ([]Snapshot, error)
	Close() error
}

// New builds a Store for the given mode. "memory" (or empty) is in-process;
// "clickhouse" writes to a ClickHouse HTTP endpoint at url (e.g.
// http://localhost:8123).
func New(mode, url string) (Store, error) { return NewRetained(mode, url, 0) }

// NewRetained is New plus the per-deployment retention TTL (SCALE-006;
// clickhouse mode only — the memory store is already window-bounded).
func NewRetained(mode, url string, retentionDays int) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("pathstore: clickhouse mode requires PROBECTL_PATHSTORE_URL")
		}
		return NewClickHouseRetained(url, retentionDays)
	default:
		return nil, fmt.Errorf("pathstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
