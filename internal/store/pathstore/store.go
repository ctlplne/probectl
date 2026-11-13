// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	ID                   string    `json:"id"`
	ObservedAt           time.Time `json:"observed_at"`
	Path                 path.Path `json:"path"`
	TrustedDiscoveryTime bool      `json:"-"` // captured from the binding database before tracing
}

// HistoryQuery bounds a snapshot read. IDs are used by stable shared views;
// when present they select only those exact rounds and supersede the time range.
type HistoryQuery struct {
	From  time.Time
	To    time.Time
	Limit int
	IDs   []string
	// MaxBytes selects a complete operation-local read instead of a browser
	// page. Positive admission returns every matching retained round or an
	// error, never a plausible prefix. Zero retains the paged API behavior.
	MaxBytes int64
}

type discoveryStartedAtKey struct{}

// WithDiscoveryStartedAt carries the control plane's PostgreSQL clock reading
// from before a trace began. Path/context bindings use that same clock, so a
// context assigned during a trace cannot authorize its earlier observations.
// This value is server-owned and is never parsed from a request payload.
func WithDiscoveryStartedAt(ctx context.Context, startedAt time.Time) context.Context {
	if startedAt.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, discoveryStartedAtKey{}, startedAt.UTC())
}

func discoveryStartedAt(ctx context.Context) (time.Time, bool) {
	if startedAt, ok := ctx.Value(discoveryStartedAtKey{}).(time.Time); ok && !startedAt.IsZero() {
		return startedAt, true
	}
	return time.Now().UTC(), false
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

// xNew builds a Store for the given mode. "memory" (or empty) is in-process;
// "clickhouse" writes to a ClickHouse HTTP endpoint at url (e.g.
// http://localhost:8123).
func xNew(mode, url string) (Store, error) { return NewRetained(mode, url, 0) }

// NewRetained is xNew plus the per-deployment retention TTL (SCALE-006;
// clickhouse mode only — the memory store is already window-bounded).
func NewRetained(mode, url string, retentionDays int) (Store, error) {
	return NewRetainedWithClient(mode, url, retentionDays, nil)
}

// NewRetainedWithClient is NewRetained with an optional hardened ClickHouse
// client. It keeps credentials out of URL userinfo while preserving the same
// storage-layer tenant enforcement and schema migration path.
func NewRetainedWithClient(mode, url string, retentionDays int, client *http.Client) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("pathstore: clickhouse mode requires PROBECTL_PATHSTORE_URL")
		}
		return NewClickHouseRetainedWithClient(url, retentionDays, client)
	default:
		return nil, fmt.Errorf("pathstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
