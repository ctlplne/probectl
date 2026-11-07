// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package flowsnapshot stores short-lived, creator-private Explorer results.
// PostgreSQL enforces tenant scope; encrypted, tenant-prefixed objects carry
// the materialized rows. Neither keys nor page membership live in process RAM
// between requests (docs/guardrails.md G7-1, G7-3, G7-6).
package flowsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	MaxRows                  = math.MaxInt32
	MaxPageRows              = 5000
	DefaultLifetime          = 15 * time.Minute
	DefaultExportBytes int64 = 256 << 20
	chunkRows                = 5000
	objectPrefix             = "flow-explorer/snapshots/"
)

var (
	ErrNotFound     = errors.New("flow snapshot not found or no longer available")
	ErrCursor       = errors.New("invalid flow snapshot cursor")
	ErrBudget       = errors.New("flow snapshot storage budget exceeded")
	ErrIntegrity    = errors.New("flow snapshot integrity check failed")
	ErrEncryption   = errors.New("flow snapshots require configured at-rest encryption")
	ErrInvalidating = sourceepoch.ErrInvalidating
)

// Scope comes from the authenticated principal, never the query grammar.
type Scope struct{ TenantID, Owner string }

func (s Scope) validate() error {
	if !canonicalID(s.TenantID) {
		return tenancy.ErrNoTenant
	}
	if strings.TrimSpace(s.Owner) == "" || len(s.Owner) > 1024 {
		return ErrNotFound
	}
	return nil
}

func canonicalID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, ch := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Config bounds cache cost independently of query row counts and time ranges.
type Config struct {
	Lifetime                                time.Duration
	TenantBytes, SnapshotBytes, ObjectBytes int64
	ExportBytes                             int64
	TempDir                                 string
}

// DefaultConfig exposes the existing bounded cache policy to trusted
// composition roots without requiring them to duplicate storage defaults.
func DefaultConfig() Config { return (Config{}).defaults() }

func (c Config) defaults() Config {
	if c.Lifetime <= 0 {
		c.Lifetime = DefaultLifetime
	}
	if c.TenantBytes <= 0 {
		c.TenantBytes = 512 << 20
	}
	if c.SnapshotBytes <= 0 {
		c.SnapshotBytes = 128 << 20
	}
	if c.ObjectBytes <= 0 {
		c.ObjectBytes = 64 << 20
	}
	if c.ExportBytes <= 0 {
		c.ExportBytes = DefaultExportBytes
	}
	return c
}

// The encrypted manifest is one admitted object, not an independent row or
// reference-count quota. Its actual bytes also count toward SnapshotBytes and
// tenant storage admission. Both existing positive profiles are raiseable.
func (c Config) privateHeaderBytes() int64 {
	return min(c.ObjectBytes, c.SnapshotBytes)
}

// Input is a fully authorized, bounded materialization. Rows retain exact JSON
// strings for counters; Header carries global Other, totals and chart/matrix
// membership once. Validity is an internal source-policy receipt, not grammar.
// ValidUntil is the earliest required input expiry, or the cache expiry when
// that source's retention is explicitly unlimited. It MUST NOT be inferred
// from the requested window's possibly empty prefix.
type Input struct {
	Query, Header, Validity json.RawMessage
	Rows                    []json.RawMessage
	ValidUntil              time.Time
}

// Authorize rechecks all stored field/source permissions before any object is
// read. Validate rechecks current source retention/coverage on every read and
// at publication; a cache cannot lengthen the source's retention clock.
type Authorize func(context.Context, Scope, []string) error
type Validate func(context.Context, Scope, json.RawMessage) error

type Header struct {
	SnapshotID   string          `json:"snapshot_id"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Query        json.RawMessage `json:"query"`
	Data         json.RawMessage `json:"data"`
	SelectedRows int             `json:"selected_rows"`
	PageSize     int             `json:"page_size"`
}

type Page struct {
	Header
	Rows       []json.RawMessage `json:"rows"`
	Offset     int               `json:"offset"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type epoch struct {
	Generation   int64
	Invalidating bool
}

// manifest's entire public header is authenticated as AAD for Private. The
// private header holds the per-snapshot data/MAC keys and object digests. Its
// keys are never exported, even in a redacted portability bundle.
type manifest struct {
	Scope
	ID, QueryHash, Lane  string
	Generation           int64
	CreatedAt, ExpiresAt time.Time
	Rows, PageSize       int
	Permissions          []string
	Private              string `json:"-"`
	ChargedBytes         int64  `json:"-"`
	Ready                bool   `json:"-"`
}

type repository interface {
	lease(context.Context, string, bool, func(context.Context) error) error
	state(context.Context, string) (epoch, error)
	reserve(context.Context, manifest, int64) error
	publish(context.Context, manifest) error
	get(context.Context, Scope, string) (manifest, error)
	remove(context.Context, string, string) error
	expired(context.Context, string, time.Time, int) ([]manifest, error)
	beginInvalidation(context.Context, string, string, Preparation) (bool, error)
	endInvalidation(context.Context, string, string, bool) error
	clear(context.Context, string) error
	any(context.Context, string) (bool, error)
	reclaimable(context.Context, string, time.Time) (bool, error)
}
