// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/breaker"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Quarantine supervisor (decision D-62). With PROBECTL_SILO_FAILURE_MODE=
// quarantine the startup preconditions that used to refuse startup for every
// tenant — the residency preflight (DPR-324), the Postgres silo catch-up
// (ARCH-001), the reader credential check (DPR-327) and the reader-scope
// catch-up and proof (DPR-323/326/328) — are evaluated per tenant instead. A
// tenant that fails one is entered into the process quarantine registry BEFORE
// the router is published, so no request ever routes to it; every other tenant
// starts normally. The supervisor then re-runs the failed checks every recheck
// interval and releases each tenant whose checks pass, with no restart.
//
// Every transition is audited on the provider stream (with the operator-side
// cause, fix and replica) and on the tenant's own chain (reason and plane
// only), and mirrored into tenant_quarantine for the provider console.

// QuarantineActor is the audit actor of every quarantine transition.
const QuarantineActor = "system:silo-quarantine"

// The audit actions of the quarantine transitions.
const (
	AuditTenantQuarantined = "tenant.quarantine_entered"
	AuditTenantReleased    = "tenant.quarantine_released"
)

// quarantineCheckTimeout bounds one tenant's checks, so a plane that accepts
// connections but never answers cannot stall boot or the supervisor.
const quarantineCheckTimeout = 45 * time.Second

// quarantineStaleIntervals: a replica row not refreshed for this many recheck
// intervals belongs to a replica that is gone; the supervisor deletes it.
const quarantineStaleIntervals = 10

// TenantChecks is what the supervisor re-runs per tenant — the Provisioner.
type TenantChecks interface {
	ValidResidency(name string) bool
	CatchUp(ctx context.Context, tenantID string) error
	CatchUpReaderScope(ctx context.Context, tenantID, residency string) error
}

// IsolatedTenant is one siloed or hybrid registry row.
type IsolatedTenant struct {
	ID, Model, Status, Residency string
}

// QuarantineSupervisor evaluates, holds and releases per-tenant quarantine.
type QuarantineSupervisor struct {
	pool         *pgxpool.Pool
	checks       TenantChecks
	registry     *tenancy.Quarantine
	readerScoped bool
	readerGap    func(residency string) error
	planes       []string
	interval     time.Duration
	replica      string
	log          *slog.Logger

	// Seams: production lists the registry and writes Postgres.
	list    func(ctx context.Context) ([]IsolatedTenant, error)
	persist func(ctx context.Context, n quarantineNotice) error
	tenant  func(ctx context.Context, n quarantineNotice) error
	sync    func(ctx context.Context, held []tenancy.QuarantineEntry) error

	mu      sync.Mutex
	pending []*quarantineNotice
}

// quarantineNotice is one transition still to be audited.
type quarantineNotice struct {
	entry        tenancy.QuarantineEntry
	entered      bool // false = released
	why          string
	providerDone bool
	tenantDone   bool
}

// QuarantineConfig wires a supervisor.
type QuarantineConfig struct {
	Pool     *pgxpool.Pool
	Checks   TenantChecks
	Registry *tenancy.Quarantine
	// ReaderScoped: a tenant-scoped store reads as the reader login, so the
	// reader credential and scope proof apply (DPR-323).
	ReaderScoped bool
	// ReaderGap reports a plane the reader has no credential for (DPR-327).
	ReaderGap func(residency string) error
	Planes    []string
	Interval  time.Duration
	Log       *slog.Logger
}

// NewQuarantineSupervisor builds the supervisor. The replica identity names
// this process in the provider view and in the audit events.
func NewQuarantineSupervisor(cfg QuarantineConfig) *QuarantineSupervisor {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Registry == nil {
		cfg.Registry = tenancy.CurrentQuarantine()
	}
	s := &QuarantineSupervisor{
		pool: cfg.Pool, checks: cfg.Checks, registry: cfg.Registry,
		readerScoped: cfg.ReaderScoped, readerGap: cfg.ReaderGap, planes: cfg.Planes,
		interval: cfg.Interval, replica: replicaIdentity(), log: cfg.Log,
	}
	s.list = s.listIsolated
	s.persist = s.persistProvider
	s.tenant = s.appendTenantNotice
	s.sync = s.syncRows
	return s
}

// Replica is this process's identity in the provider view.
func (s *QuarantineSupervisor) Replica() string { return s.replica }

func replicaIdentity() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "control"
	}
	return fmt.Sprintf("%s/%d/%x", host, os.Getpid(), time.Now().UnixNano())
}

const isolatedTenantsQuery = `SELECT id::text, isolation_model, status, residency FROM tenants
	 WHERE isolation_model IN ('siloed','hybrid') AND status <> 'deleted'
	 ORDER BY id`

func (s *QuarantineSupervisor) listIsolated(ctx context.Context) ([]IsolatedTenant, error) {
	var out []IsolatedTenant
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, isolatedTenantsQuery)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t IsolatedTenant
			if err := rows.Scan(&t.ID, &t.Model, &t.Status, &t.Residency); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// Boot evaluates every siloed and hybrid tenant and quarantines each one that
// fails a precondition. It runs BEFORE the router is published. Only a
// failure to read the tenant registry itself is returned (refuse startup):
// without the registry no tenant can be routed safely.
func (s *QuarantineSupervisor) Boot(ctx context.Context) ([]tenancy.QuarantineEntry, error) {
	tenants, err := s.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("silo quarantine: read the tenant registry: %w", err)
	}
	down := map[string]tenancy.QuarantineEntry{}
	for _, t := range tenants {
		e := s.Evaluate(ctx, t, down)
		if e == nil {
			continue
		}
		s.enter(*e)
	}
	held := s.registry.List()
	if len(held) > 0 {
		s.log.Warn("silo quarantine: tenants quarantined at startup; every other tenant starts normally (D-62)",
			"quarantined", len(held), "isolated_tenants", len(tenants))
	}
	return held, nil
}

func (s *QuarantineSupervisor) enter(e tenancy.QuarantineEntry) {
	prevReason := ""
	for _, held := range s.registry.List() {
		if held.TenantID == strings.ToLower(e.TenantID) {
			prevReason = string(held.Reason)
		}
	}
	stored, fresh := s.registry.Enter(e)
	if !fresh && prevReason == string(stored.Reason) {
		s.log.Debug("silo quarantine: tenant still fails its check", "tenant", stored.TenantID, "reason", string(stored.Reason))
		return
	}
	s.log.Warn("silo quarantine: tenant quarantined — its reads and writes are refused until the check passes (D-62)",
		"tenant", stored.TenantID, "reason", string(stored.Reason), "plane", stored.Plane,
		"detail", stored.Detail, "fix", stored.Remedy, "cause_changed", !fresh)
	if fresh {
		s.queue(&quarantineNotice{entry: stored, entered: true})
	}
}

func (s *QuarantineSupervisor) release(e tenancy.QuarantineEntry, why string) {
	released, ok := s.registry.Release(e.TenantID)
	if !ok {
		return
	}
	s.log.Info("silo quarantine: tenant released — its checks pass again (D-62)",
		"tenant", released.TenantID, "reason", string(released.Reason), "plane", released.Plane, "why", why,
		"quarantined_for", time.Since(released.Since).Round(time.Second).String())
	s.queue(&quarantineNotice{entry: released, why: why})
}

func (s *QuarantineSupervisor) queue(n *quarantineNotice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, n)
}

// Evaluate runs one tenant's preconditions in startup order and returns the
// first that fails, or nil when the tenant is safe to route. down memoizes
// planes found unreachable in this pass, so tenants sharing a dead plane do
// not each wait out its timeout.
func (s *QuarantineSupervisor) Evaluate(ctx context.Context, t IsolatedTenant, down map[string]tenancy.QuarantineEntry) *tenancy.QuarantineEntry {
	ctx, cancel := context.WithTimeout(ctx, quarantineCheckTimeout)
	defer cancel()
	entry := func(reason tenancy.QuarantineReason, detail string) *tenancy.QuarantineEntry {
		return &tenancy.QuarantineEntry{TenantID: t.ID, Reason: reason, Plane: t.Residency,
			Detail: detail, Remedy: quarantineRemedy(reason, t.Residency)}
	}
	if t.Residency != "" && !s.checks.ValidResidency(t.Residency) {
		return entry(tenancy.QuarantinePlaneMissing, fmt.Sprintf(
			"the tenant is pinned to data plane %q, which PROBECTL_DATAPLANES does not name (configured: %s); routing it would send its telemetry to the default plane (DPR-324)",
			t.Residency, planeList(s.planes)))
	}
	if t.Model == string(tenancy.IsolationSiloed) && (t.Status == "active" || t.Status == "suspended") {
		if err := s.checks.CatchUp(ctx, t.ID); err != nil {
			return entry(tenancy.QuarantineSchemaCatchUpFailed, "silo schema catch-up: "+err.Error())
		}
	}
	if !s.readerScoped {
		return nil
	}
	if s.readerGap != nil && t.Residency != "" {
		if err := s.readerGap(t.Residency); err != nil {
			return entry(tenancy.QuarantineReaderCredentialMissing, err.Error())
		}
	}
	if d, ok := down[t.Residency]; ok {
		return entry(d.Reason, d.Detail)
	}
	err := s.checks.CatchUpReaderScope(ctx, t.ID, t.Residency)
	if err == nil {
		return nil
	}
	if planeUnreachable(err) {
		e := entry(tenancy.QuarantinePlaneUnreachable, "reader-scope proof could not reach the plane: "+err.Error())
		down[t.Residency] = *e
		return e
	}
	return entry(tenancy.QuarantineReaderScopeUnproven, "reader-scope proof: "+err.Error())
}

// planeUnreachable reports a transport-level failure (refused, DNS, TLS
// handshake, timeout, an open circuit breaker) as opposed to a plane that
// answered and refused the proof.
func planeUnreachable(err error) bool {
	var urlErr *url.Error
	var netErr net.Error
	return errors.Is(err, breaker.ErrOpen) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &urlErr) || errors.As(err, &netErr)
}

func planeList(planes []string) string {
	if len(planes) == 0 {
		return "none"
	}
	return strings.Join(planes, ", ")
}

func planeLabel(plane string) string {
	if plane == "" {
		return "the default plane"
	}
	return fmt.Sprintf("data plane %q", plane)
}

// quarantineRemedy is the operator-facing fix for each reason.
func quarantineRemedy(reason tenancy.QuarantineReason, plane string) string {
	switch reason {
	case tenancy.QuarantinePlaneMissing:
		return fmt.Sprintf("add %s=https://<clickhouse-host>:<port> back to PROBECTL_DATAPLANES (with its PROBECTL_DATAPLANE_BASIC_AUTH_FILES and PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES entries) and roll the control plane; the tenant is released on each replica that starts with the plane configured", plane)
	case tenancy.QuarantinePlaneUnreachable:
		return fmt.Sprintf("restore connectivity from the control plane to %s's ClickHouse (DNS, TLS trust, firewall, server health); the supervisor re-proves the reader scope every recheck interval and releases the tenant without a restart", planeLabel(plane))
	case tenancy.QuarantineReaderCredentialMissing:
		return fmt.Sprintf("add %s=/abs/path/reader-credential.json (the reader login's credential on that plane) to PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES and roll the control plane (DPR-327)", plane)
	case tenancy.QuarantineReaderScopeUnproven:
		return fmt.Sprintf("on %s's ClickHouse grant the control login SELECT ON *.* WITH GRANT OPTION and keep the reader a SQL-created, SELECT-only login (docs/lifecycle.md, 0.6.6); the supervisor re-installs and re-proves the scope and releases the tenant without a restart", planeLabel(plane))
	case tenancy.QuarantineSchemaCatchUpFailed:
		return "fix the precondition the catch-up statement names (usually PROBECTL_MIGRATE_DATABASE_URL, the migration login's privileges, or a hand-edited silo schema); the supervisor retries the catch-up and releases the tenant without a restart"
	default:
		return "see the detail; the supervisor re-checks the tenant every recheck interval"
	}
}

// Start runs the supervisor until ctx ends. Call it AFTER the router is
// published: the tenant-chain notice resolves the tenant's own schema
// through it.
func (s *QuarantineSupervisor) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *QuarantineSupervisor) run(ctx context.Context) {
	s.flush(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Recheck(ctx)
		}
	}
}

// Recheck re-evaluates every quarantined tenant once, releases the tenants
// that pass (or are no longer routed as siloed/hybrid), and flushes the
// audit notices and the provider view.
func (s *QuarantineSupervisor) Recheck(ctx context.Context) {
	held := s.registry.List()
	if len(held) > 0 {
		tenants, err := s.list(ctx)
		if err != nil {
			s.log.Warn("silo quarantine: recheck could not read the tenant registry; keeping every quarantine", "error", err.Error())
		} else {
			s.recheckHeld(ctx, held, tenants)
		}
	}
	s.flush(ctx)
}

func (s *QuarantineSupervisor) recheckHeld(ctx context.Context, held []tenancy.QuarantineEntry, tenants []IsolatedTenant) {
	byID := make(map[string]IsolatedTenant, len(tenants))
	for _, t := range tenants {
		byID[strings.ToLower(t.ID)] = t
	}
	down := map[string]tenancy.QuarantineEntry{}
	for _, e := range held {
		if ctx.Err() != nil {
			return
		}
		t, ok := byID[e.TenantID]
		if !ok {
			// Deleted, or no longer siloed/hybrid: nothing is routed to an
			// isolated target any more.
			s.release(e, "the tenant is no longer an isolated (siloed/hybrid) tenant that is routed")
			continue
		}
		next := s.Evaluate(ctx, t, down)
		if ctx.Err() != nil {
			return // shutting down: never release on a canceled check
		}
		if next == nil {
			s.release(e, "every startup check passes again")
			continue
		}
		s.enter(*next) // refresh the cause (Since is kept)
	}
}

// flush writes the pending audit notices and refreshes the provider view.
// A notice that fails stays pending and is retried on the next recheck.
func (s *QuarantineSupervisor) flush(ctx context.Context) {
	s.mu.Lock()
	pending := s.pending
	s.pending = nil
	s.mu.Unlock()
	var keep []*quarantineNotice
	for _, n := range pending {
		if !n.providerDone {
			if err := s.persist(ctx, *n); err != nil {
				s.log.Warn("silo quarantine: provider audit of a transition failed; retrying", "tenant", n.entry.TenantID, "error", err.Error())
			} else {
				n.providerDone = true
			}
		}
		if !n.tenantDone {
			if err := s.tenant(ctx, *n); err != nil {
				s.log.Warn("silo quarantine: tenant-chain audit of a transition failed; retrying", "tenant", n.entry.TenantID, "error", err.Error())
			} else {
				n.tenantDone = true
			}
		}
		if !n.providerDone || !n.tenantDone {
			keep = append(keep, n)
		}
	}
	if len(keep) > 0 {
		s.mu.Lock()
		s.pending = append(keep, s.pending...)
		s.mu.Unlock()
	}
	if err := s.sync(ctx, s.registry.List()); err != nil {
		s.log.Warn("silo quarantine: provider view refresh failed", "error", err.Error())
	}
}

func (n quarantineNotice) action() string {
	if n.entered {
		return AuditTenantQuarantined
	}
	return AuditTenantReleased
}

// persistProvider appends the transition to the provider stream and applies
// it to tenant_quarantine in one provider transaction.
func (s *QuarantineSupervisor) persistProvider(ctx context.Context, n quarantineNotice) error {
	e := n.entry
	data := map[string]any{
		"reason": string(e.Reason), "plane": e.Plane, "detail": e.Detail, "remedy": e.Remedy,
		"replica": s.replica, "since": e.Since.UTC().Format(time.RFC3339), "decision": "D-62",
	}
	if !n.entered {
		data["released_because"] = n.why
	}
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		if _, err := audit.ProviderAppendTx(ctx, q, QuarantineActor, n.action(), e.TenantID, data); err != nil {
			return err
		}
		if n.entered {
			return upsertQuarantineRow(ctx, q, s.replica, e)
		}
		_, err := q.Exec(ctx, `DELETE FROM tenant_quarantine WHERE tenant = $1::uuid AND replica = $2`, e.TenantID, s.replica)
		return err
	})
}

func upsertQuarantineRow(ctx context.Context, q tenancy.Querier, replica string, e tenancy.QuarantineEntry) error {
	_, err := q.Exec(ctx, `INSERT INTO tenant_quarantine (tenant, replica, reason, plane, detail, remedy, since, checked_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (tenant, replica) DO UPDATE
		   SET reason = EXCLUDED.reason, plane = EXCLUDED.plane, detail = EXCLUDED.detail,
		       remedy = EXCLUDED.remedy, checked_at = now()`,
		e.TenantID, replica, string(e.Reason), e.Plane, e.Detail, e.Remedy, e.Since)
	return err
}

// appendTenantNotice writes the transition to the tenant's own audit chain:
// the reason and plane, never the operator-side detail.
func (s *QuarantineSupervisor) appendTenantNotice(ctx context.Context, n quarantineNotice) error {
	e := n.entry
	data := map[string]any{"reason": string(e.Reason), "plane": e.Plane, "since": e.Since.UTC().Format(time.RFC3339), "decision": "D-62"}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(e.TenantID))
	return tenancy.InTenantQuarantineNotice(tctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, QuarantineActor, n.action(), e.TenantID, data)
		return err
	})
}

// syncRows refreshes this replica's rows (heartbeat), drops the rows of
// tenants it no longer holds, and deletes rows of replicas that are gone.
func (s *QuarantineSupervisor) syncRows(ctx context.Context, held []tenancy.QuarantineEntry) error {
	ids := make([]string, 0, len(held))
	for _, e := range held {
		ids = append(ids, e.TenantID)
	}
	stale := time.Duration(quarantineStaleIntervals) * s.interval
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		for _, e := range held {
			if err := upsertQuarantineRow(ctx, q, s.replica, e); err != nil {
				return err
			}
		}
		if _, err := q.Exec(ctx, `DELETE FROM tenant_quarantine WHERE replica = $1 AND NOT (tenant::text = ANY($2::text[]))`, s.replica, ids); err != nil {
			return err
		}
		_, err := q.Exec(ctx, `DELETE FROM tenant_quarantine WHERE checked_at < now() - make_interval(secs => $1)`, stale.Seconds())
		return err
	})
}

// LoadReplicaQuarantine (D-62) copies into q every quarantine a live serving
// replica holds — rows of tenant_quarantine refreshed within freshWithin — so
// a one-shot command (mcp-stdio, mcp-token, bootstrap-admin, …) refuses a
// tenant the serving replicas have quarantined instead of serving it from a
// process that never ran the startup checks. A database that predates
// migration 0130 can hold no quarantine and loads nothing.
func LoadReplicaQuarantine(ctx context.Context, pool *pgxpool.Pool, q *tenancy.Quarantine, freshWithin time.Duration) (int, error) {
	var entries []tenancy.QuarantineEntry
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, tx tenancy.Querier) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('public.tenant_quarantine') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (tenant) tenant::text, reason, plane, detail, remedy, since
			   FROM tenant_quarantine
			  WHERE checked_at >= now() - make_interval(secs => $1)
			  ORDER BY tenant, since`, freshWithin.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e tenancy.QuarantineEntry
			var reason string
			if err := rows.Scan(&e.TenantID, &reason, &e.Plane, &e.Detail, &e.Remedy, &e.Since); err != nil {
				return err
			}
			e.Reason = tenancy.QuarantineReason(reason)
			entries = append(entries, e)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, fmt.Errorf("silo quarantine: read the replicas' quarantine view: %w", err)
	}
	for _, e := range entries {
		q.Enter(e)
	}
	return len(entries), nil
}
