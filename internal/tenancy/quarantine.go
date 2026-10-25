// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Per-tenant quarantine (decision D-62). When a siloed or hybrid tenant's
// isolation targets cannot be proven safe at startup — its residency plane is
// no longer configured, unreachable, missing the reader credential, or its
// reader-scope proof fails — the control plane can either refuse to start for
// every tenant (the alpha default) or QUARANTINE just that tenant: every read
// and write of it is refused at the routing layer (the registry-backed silo
// router and InTenant's schema resolution), while every other tenant starts
// and runs normally. A supervisor re-checks the tenant and releases it once
// the fault is fixed.
//
// ELI5: when one flat's plumbing is broken, the building manager locks that
// flat's door with a note saying what is broken and who fixes it, instead of
// closing the whole building. The lock is on the door (the router), not a sign
// at reception (a handler), so no corridor leads round it.

// ErrTenantQuarantined is matched (errors.Is) by every refusal of a
// quarantined tenant's read or write.
var ErrTenantQuarantined = errors.New("tenancy: tenant is quarantined")

// QuarantineReason names the failed precondition. The values are fixed codes:
// they label the probectl_tenant_quarantined metric and the audit events.
type QuarantineReason string

// The quarantine reasons, one per startup precondition that can fail for a
// single tenant.
const (
	// QuarantinePlaneMissing: the tenant's residency plane is not in
	// PROBECTL_DATAPLANES (DPR-324). Routing it would send its telemetry to
	// the default plane, where its database was never created.
	QuarantinePlaneMissing QuarantineReason = "residency_plane_missing"
	// QuarantinePlaneUnreachable: the plane's ClickHouse could not be reached
	// to prove the tenant's reader scope (DPR-323 boot catch-up).
	QuarantinePlaneUnreachable QuarantineReason = "residency_plane_unreachable"
	// QuarantineReaderCredentialMissing: the reader login has no credential
	// for the plane (PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES, DPR-327).
	QuarantineReaderCredentialMissing QuarantineReason = "reader_credential_missing"
	// QuarantineReaderScopeUnproven: the plane answered, but the reader row
	// policy and grants could not be installed or proven (DPR-323/326/328).
	QuarantineReaderScopeUnproven QuarantineReason = "reader_scope_unproven"
	// QuarantineSchemaCatchUpFailed: the siloed tenant's Postgres schema could
	// not be brought to the current shape (ARCH-001 catch-up).
	QuarantineSchemaCatchUpFailed QuarantineReason = "silo_schema_catchup_failed"
	// QuarantineSchemaIncomplete: the siloed tenant's Postgres schema lacks a
	// tenant-owned table it must carry (DPR-385) — removed after it was
	// proven, or never created — so that table would resolve to the pooled
	// public one.
	QuarantineSchemaIncomplete QuarantineReason = "silo_schema_incomplete"
)

// QuarantineReasons lists every reason (stable order) — the metric's label set.
func QuarantineReasons() []QuarantineReason {
	return []QuarantineReason{
		QuarantinePlaneMissing,
		QuarantinePlaneUnreachable,
		QuarantineReaderCredentialMissing,
		QuarantineReaderScopeUnproven,
		QuarantineSchemaCatchUpFailed,
		QuarantineSchemaIncomplete,
	}
}

// QuarantineEntry is one quarantined tenant.
type QuarantineEntry struct {
	TenantID string
	Reason   QuarantineReason
	// Plane is the tenant's residency plane name ("" = the default plane).
	Plane string
	// Detail is the operator-facing cause: the first line of the failing
	// check's error, credentials redacted. It is shown to operators (provider
	// view, audit, logs), never to the tenant.
	Detail string
	// Remedy is the operator-facing fix.
	Remedy string
	Since  time.Time
}

// QuarantinedError is what a quarantined tenant's routed read or write
// returns. errors.Is(err, ErrTenantQuarantined) matches it.
type QuarantinedError struct{ Entry QuarantineEntry }

func (e *QuarantinedError) Error() string {
	plane := e.Entry.Plane
	if plane == "" {
		plane = "default"
	}
	return fmt.Sprintf("tenancy: tenant %s is quarantined (%s, data plane %q): %s; fix: %s (D-62)",
		e.Entry.TenantID, e.Entry.Reason, plane, e.Entry.Detail, e.Entry.Remedy)
}

// Is matches ErrTenantQuarantined.
func (e *QuarantinedError) Is(target error) bool { return target == ErrTenantQuarantined }

// TenantMessage is the refusal shown to the quarantined tenant's own users:
// which precondition failed, on which plane, that the deployment operator
// must fix it, and that access resumes by itself. It carries no internal
// error text (hostnames, statements) and no deployment vocabulary such as
// configuration keys (DPR-383): Detail and Remedy stay operator-side.
func (e *QuarantinedError) TenantMessage() string {
	plane := e.Entry.Plane
	if plane == "" {
		plane = "default"
	}
	var what string
	switch e.Entry.Reason {
	case QuarantinePlaneMissing:
		what = fmt.Sprintf("its residency data plane %q is not configured on this control plane", plane)
	case QuarantinePlaneUnreachable:
		what = fmt.Sprintf("its residency data plane %q is unreachable from this control plane", plane)
	case QuarantineReaderCredentialMissing:
		what = fmt.Sprintf("the read-only database login has no credential for its residency data plane %q", plane)
	case QuarantineReaderScopeUnproven:
		what = fmt.Sprintf("the tenant-isolation proof for its data on residency data plane %q failed", plane)
	case QuarantineSchemaCatchUpFailed:
		what = "its isolated database schema could not be brought up to date"
	case QuarantineSchemaIncomplete:
		what = "its isolated database schema is missing part of its data"
	default:
		what = "an isolation precondition failed"
	}
	return "this tenant is quarantined: " + what +
		". Every read and write is refused so its data is never served from an unproven location. " +
		"The deployment operator must fix this (the provider console lists the cause and the fix); " +
		"access resumes automatically once it is fixed"
}

// Quarantine is the process's set of quarantined tenants. The zero value is
// not usable; call NewQuarantine. All methods are safe for concurrent use and
// a nil *Quarantine is an empty registry.
type Quarantine struct {
	mu       sync.RWMutex
	entries  map[string]QuarantineEntry
	entered  atomic.Uint64
	released atomic.Uint64
	dropped  atomic.Uint64
}

// NewQuarantine builds an empty registry.
func NewQuarantine() *Quarantine {
	return &Quarantine{entries: map[string]QuarantineEntry{}}
}

// Check refuses a quarantined tenant with a *QuarantinedError.
func (q *Quarantine) Check(tenantID string) error {
	if q == nil {
		return nil
	}
	q.mu.RLock()
	e, ok := q.entries[strings.ToLower(tenantID)]
	q.mu.RUnlock()
	if !ok {
		return nil
	}
	return &QuarantinedError{Entry: e}
}

// Enter quarantines a tenant (or updates the cause of one already
// quarantined, keeping its Since). It reports whether the tenant was newly
// quarantined — the transition that is audited.
func (q *Quarantine) Enter(e QuarantineEntry) (QuarantineEntry, bool) {
	e.TenantID = strings.ToLower(e.TenantID)
	e.Detail = RedactQuarantineDetail(e.Detail)
	q.mu.Lock()
	defer q.mu.Unlock()
	prev, existed := q.entries[e.TenantID]
	switch {
	case existed:
		e.Since = prev.Since
	case e.Since.IsZero():
		e.Since = time.Now().UTC()
	}
	q.entries[e.TenantID] = e
	if !existed {
		q.entered.Add(1)
	}
	return e, !existed
}

// Release lifts a tenant's quarantine, returning the entry it held.
func (q *Quarantine) Release(tenantID string) (QuarantineEntry, bool) {
	if q == nil {
		return QuarantineEntry{}, false
	}
	id := strings.ToLower(tenantID)
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[id]
	if ok {
		delete(q.entries, id)
		q.released.Add(1)
	}
	return e, ok
}

// List returns every entry, ordered by tenant id.
func (q *Quarantine) List() []QuarantineEntry {
	if q == nil {
		return nil
	}
	q.mu.RLock()
	out := make([]QuarantineEntry, 0, len(q.entries))
	for _, e := range q.entries {
		out = append(out, e)
	}
	q.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

// CountByReason counts quarantined tenants per reason (every reason present,
// zero included) — the probectl_tenant_quarantined gauge.
func (q *Quarantine) CountByReason() map[QuarantineReason]int {
	out := map[QuarantineReason]int{}
	for _, r := range QuarantineReasons() {
		out[r] = 0
	}
	for _, e := range q.List() {
		out[e.Reason]++
	}
	return out
}

// Transitions reports how many tenants entered and left quarantine since the
// process started.
func (q *Quarantine) Transitions() (entered, released uint64) {
	if q == nil {
		return 0, 0
	}
	return q.entered.Load(), q.released.Load()
}

// NoteNoticeDropped counts a tenant-chain quarantine receipt that could not
// be written within its bounded retries (recorded on the provider stream
// instead).
func (q *Quarantine) NoteNoticeDropped() {
	if q != nil {
		q.dropped.Add(1)
	}
}

// NoticesDropped reports NoteNoticeDropped's count.
func (q *Quarantine) NoticesDropped() uint64 {
	if q == nil {
		return 0
	}
	return q.dropped.Load()
}

var currentQuarantine atomic.Pointer[Quarantine]

// SetQuarantine installs the process's quarantine registry (the attach seam,
// next to SetRouter). nil installs an empty one.
func SetQuarantine(q *Quarantine) {
	if q == nil {
		q = NewQuarantine()
	}
	currentQuarantine.Store(q)
}

// CurrentQuarantine returns the installed registry (never nil).
func CurrentQuarantine() *Quarantine {
	if q := currentQuarantine.Load(); q != nil {
		return q
	}
	q := NewQuarantine()
	if currentQuarantine.CompareAndSwap(nil, q) {
		return q
	}
	return currentQuarantine.Load()
}

// CheckQuarantine refuses tenantID if the installed registry quarantines it.
// A quarantine-notice context (InTenantQuarantineNotice) is not exempt here:
// only schema resolution honors it.
func CheckQuarantine(tenantID string) error { return CurrentQuarantine().Check(tenantID) }

type quarantineNoticeKey struct{}

// InTenantQuarantineNotice runs fn exactly like InTenant (same role, GUC, RLS
// and schema routing) for a QUARANTINED tenant, so the quarantine supervisor
// can append the enter/release receipt to the tenant's OWN audit chain. It is
// the one sanctioned exemption from the quarantine refusal and it reaches
// Postgres only: the ClickHouse planes, whose proof failed, are never routed
// under it. Callers are pinned by TestQuarantineNoticeHasOneCaller — fn must
// do nothing but append that receipt.
func InTenantQuarantineNotice(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, Scope) error) error {
	return InTenant(context.WithValue(ctx, quarantineNoticeKey{}, true), pool, fn)
}

// noticeTables are the tables a quarantine notice needs in the tenant's own
// schema: its audit chain. A silo without them gets no tenant-chain notice
// (DPR-368), never one written to the pooled table.
func noticeTables(ctx context.Context) []string {
	if QuarantineNoticeContext(ctx) {
		return []string{"audit_events"}
	}
	return nil
}

// QuarantineNoticeContext reports whether ctx is an InTenantQuarantineNotice
// transaction. Only Postgres schema resolution may honor it.
func QuarantineNoticeContext(ctx context.Context) bool {
	v, _ := ctx.Value(quarantineNoticeKey{}).(bool)
	return v
}

// pgQuarantineCheck is InTenant's own quarantine refusal (defense in depth
// under the router's): a quarantined tenant's Postgres transaction is refused
// before it begins, unless it is the quarantine notice itself.
func pgQuarantineCheck(ctx context.Context, tenantID string) error {
	if QuarantineNoticeContext(ctx) {
		return nil
	}
	return CheckQuarantine(tenantID)
}

var userinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// maxQuarantineDetail bounds the operator-facing cause.
const maxQuarantineDetail = 400

// RedactQuarantineDetail reduces an error to its first line, strips URL
// userinfo and bounds its length, so a quarantine cause can be shown to
// operators and written to audit without carrying credentials.
func RedactQuarantineDetail(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = userinfoRe.ReplaceAllString(s, "${1}")
	if len(s) > maxQuarantineDetail {
		s = s[:maxQuarantineDetail] + "…"
	}
	return s
}
