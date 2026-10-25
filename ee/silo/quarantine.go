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
// Enforcement is per replica (each proves the tenant for itself); the audit
// trail is per TENANT TRANSITION (DPR-381): each replica keeps its row in
// tenant_quarantine, and the provider stream and the tenant's own chain record
// tenant.quarantine_entered only when the first live replica starts holding
// the tenant and tenant.quarantine_released only when the last one stops — so
// restarts, rollouts and several replicas do not repeat the events.

// QuarantineActor is the audit actor of every quarantine transition.
const QuarantineActor = "system:silo-quarantine"

// The audit actions of the quarantine.
const (
	AuditTenantQuarantined = "tenant.quarantine_entered"
	AuditTenantReleased    = "tenant.quarantine_released"
	// AuditQuarantineCauseChanged: a replica still holds the tenant, for a
	// different reason (provider stream only).
	AuditQuarantineCauseChanged = "tenant.quarantine_cause_changed"
	// AuditQuarantineNoticeProviderOnly: a tenant-chain receipt could not be
	// written — the silo schema is missing, the tenant is erased, or the
	// bounded retries ran out — so it is recorded on the provider stream
	// only (provider stream only).
	AuditQuarantineNoticeProviderOnly = "tenant.quarantine_notice_provider_only"
)

// DefaultQuarantineCheckTimeout bounds EACH check of a tenant (the silo
// schema catch-up, the reader-scope proof) separately (DPR-380). It is
// generous so a long but healthy catch-up can finish; a check that still
// overruns it is that tenant's own fault and is retried every recheck.
const DefaultQuarantineCheckTimeout = 5 * time.Minute

// quarantineStaleIntervals: a replica row not refreshed for this many recheck
// intervals belongs to a replica that is gone. Rows inside the window are the
// tenant's live holders.
const quarantineStaleIntervals = 10

// maxNoticeAttempts bounds the retries of one tenant-chain receipt; after
// that it is recorded on the provider stream only and counted (DPR-381).
const maxNoticeAttempts = 20

// TenantChecks is what the supervisor re-runs per tenant — the Provisioner.
type TenantChecks interface {
	ValidResidency(name string) bool
	CatchUp(ctx context.Context, tenantID string) error
	CatchUpReaderScope(ctx context.Context, tenantID, residency string) error
	// MissingSiloTables reports, per siloed tenant, the tenant-owned tables
	// its schema lacks (verification only, DPR-385).
	MissingSiloTables(ctx context.Context, tenantIDs []string) (map[string][]string, error)
}

// IsolatedTenant is one siloed or hybrid registry row.
type IsolatedTenant struct {
	ID, Model, Status, Residency string
}

// quarantineStore persists each replica's quarantines and records the tenant
// transitions they make. The Postgres store (quarantine_store.go) does each
// operation in one provider transaction under a per-tenant advisory lock, so
// two replicas never both see themselves as the first or last holder.
type quarantineStore interface {
	// hold refreshes this replica's row for e. It reports whether no live
	// replica held the tenant before (the provider-stream entered event was
	// then written in the same transaction).
	hold(ctx context.Context, replica string, e tenancy.QuarantineEntry, live time.Duration) (entered bool, err error)
	// drop deletes this replica's row; released reports that no live holder
	// remains (the released event was then written).
	drop(ctx context.Context, replica string, e tenancy.QuarantineEntry, live time.Duration, why string) (released bool, err error)
	// mine lists this replica's rows (left by an earlier process on the same
	// replica identity).
	mine(ctx context.Context, replica string) ([]tenancy.QuarantineEntry, error)
	// prune deletes rows of replicas that are gone and returns the tenants
	// that thereby lost their last live holder (released events written).
	prune(ctx context.Context, live time.Duration) ([]tenancy.QuarantineEntry, error)
	// record appends one provider-stream event.
	record(ctx context.Context, action, tenantID string, data map[string]any) error
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
	checkTimeout time.Duration
	replica      string
	log          *slog.Logger

	// Seams: production lists the registry and writes Postgres.
	list   func(ctx context.Context) ([]IsolatedTenant, error)
	store  quarantineStore
	tenant func(ctx context.Context, n tenantNotice) error

	mu      sync.Mutex
	drops   map[string]pendingDrop
	notices []*tenantNotice
}

// pendingDrop is a release this replica has applied in memory but not yet
// persisted.
type pendingDrop struct {
	entry        tenancy.QuarantineEntry
	why          string
	providerOnly bool
}

// tenantNotice is one tenant transition still to be written on the tenant's
// own chain.
type tenantNotice struct {
	entry        tenancy.QuarantineEntry
	entered      bool // false = released
	providerOnly bool // the tenant has no chain to write to (erased)
	attempts     int
}

func (n tenantNotice) action() string {
	if n.entered {
		return AuditTenantQuarantined
	}
	return AuditTenantReleased
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
	// CheckTimeout bounds each check separately (default
	// DefaultQuarantineCheckTimeout).
	CheckTimeout time.Duration
	// Replica is this process's stable identity in tenant_quarantine and
	// the audit events (default: the host name, which is the pod name on
	// Kubernetes, so a restarted container keeps it).
	Replica string
	Log     *slog.Logger
}

// NewQuarantineSupervisor builds the supervisor.
func NewQuarantineSupervisor(cfg QuarantineConfig) *QuarantineSupervisor {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = DefaultQuarantineCheckTimeout
	}
	if cfg.Registry == nil {
		cfg.Registry = tenancy.CurrentQuarantine()
	}
	if cfg.Replica == "" {
		cfg.Replica = replicaIdentity()
	}
	s := &QuarantineSupervisor{
		pool: cfg.Pool, checks: cfg.Checks, registry: cfg.Registry,
		readerScoped: cfg.ReaderScoped, readerGap: cfg.ReaderGap, planes: cfg.Planes,
		interval: cfg.Interval, checkTimeout: cfg.CheckTimeout, replica: cfg.Replica, log: cfg.Log,
		drops: map[string]pendingDrop{},
	}
	s.list = s.listIsolated
	s.store = pgQuarantineStore{pool: cfg.Pool}
	s.tenant = s.appendTenantNotice
	return s
}

// Replica is this process's identity in the provider view.
func (s *QuarantineSupervisor) Replica() string { return s.replica }

func replicaIdentity() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "control"
	}
	if len(host) > 200 {
		host = host[:200]
	}
	return host
}

// live is the window inside which a replica row counts as a holder.
func (s *QuarantineSupervisor) live() time.Duration {
	return time.Duration(quarantineStaleIntervals) * s.interval
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
		if e := s.Evaluate(ctx, t, down); e != nil {
			s.enter(*e)
		}
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
	s.mu.Lock()
	delete(s.drops, stored.TenantID) // held again before its release was persisted
	s.mu.Unlock()
	if !fresh && prevReason == string(stored.Reason) {
		s.log.Debug("silo quarantine: tenant still fails its check", "tenant", stored.TenantID, "reason", string(stored.Reason))
		return
	}
	s.log.Warn("silo quarantine: tenant quarantined — its reads and writes are refused until the check passes (D-62)",
		"tenant", stored.TenantID, "reason", string(stored.Reason), "plane", stored.Plane,
		"detail", stored.Detail, "fix", stored.Remedy, "cause_changed", !fresh, "replica", s.replica)
}

func (s *QuarantineSupervisor) release(e tenancy.QuarantineEntry, why string, providerOnly bool) {
	released, ok := s.registry.Release(e.TenantID)
	if !ok {
		return
	}
	s.log.Info("silo quarantine: tenant released — its checks pass again (D-62)",
		"tenant", released.TenantID, "reason", string(released.Reason), "plane", released.Plane, "why", why,
		"quarantined_for", time.Since(released.Since).Round(time.Second).String(), "replica", s.replica)
	s.mu.Lock()
	s.drops[released.TenantID] = pendingDrop{entry: released, why: why, providerOnly: providerOnly}
	s.mu.Unlock()
}

// checkResult is one bounded check's outcome.
type checkResult struct {
	err      error
	timedOut bool // the check's own budget ran out (not the caller's)
}

// bounded runs one check on its own budget (DPR-380): the schema catch-up and
// the reader-scope proof never share one, so a slow catch-up cannot starve
// the proof into a false "unreachable".
func (s *QuarantineSupervisor) bounded(ctx context.Context, fn func(context.Context) error) checkResult {
	cctx, cancel := context.WithTimeout(ctx, s.checkTimeout)
	defer cancel()
	err := fn(cctx)
	return checkResult{err: err, timedOut: err != nil && ctx.Err() == nil && errors.Is(cctx.Err(), context.DeadlineExceeded)}
}

// Evaluate runs one tenant's preconditions in startup order and returns the
// first that fails, or nil when the tenant is safe to route. down memoizes
// planes whose connections were REFUSED in this pass (a dial error or an open
// breaker — never a timeout, which may be the tenant's own slow check or a
// lock wait), so tenants sharing a dead plane do not each wait on it.
func (s *QuarantineSupervisor) Evaluate(ctx context.Context, t IsolatedTenant, down map[string]tenancy.QuarantineEntry) *tenancy.QuarantineEntry {
	return s.evaluate(ctx, t, down, true)
}

// evaluate is Evaluate; repair=false skips the schema catch-up, which would
// otherwise silently recreate a missing table EMPTY: a tenant quarantined
// for an incomplete silo stays quarantined until the operator restores the
// table or rolls the control plane (whose startup catch-up recreates it).
func (s *QuarantineSupervisor) evaluate(ctx context.Context, t IsolatedTenant, down map[string]tenancy.QuarantineEntry, repair bool) *tenancy.QuarantineEntry {
	entry := func(reason tenancy.QuarantineReason, detail, remedy string) *tenancy.QuarantineEntry {
		if remedy == "" {
			remedy = quarantineRemedy(reason, t.Residency)
		}
		return &tenancy.QuarantineEntry{TenantID: t.ID, Reason: reason, Plane: t.Residency, Detail: detail, Remedy: remedy}
	}
	if t.Residency != "" && !s.checks.ValidResidency(t.Residency) {
		return entry(tenancy.QuarantinePlaneMissing, fmt.Sprintf(
			"the tenant is pinned to data plane %q, which PROBECTL_DATAPLANES does not name (configured: %s); routing it would send its telemetry to the default plane (DPR-324)",
			t.Residency, planeList(s.planes)), "")
	}
	if repair && t.Model == string(tenancy.IsolationSiloed) && (t.Status == "active" || t.Status == "suspended") {
		r := s.bounded(ctx, func(ctx context.Context) error { return s.checks.CatchUp(ctx, t.ID) })
		switch {
		case r.timedOut:
			return entry(tenancy.QuarantineSchemaCatchUpFailed,
				fmt.Sprintf("silo schema catch-up did not finish within %s: %v", s.checkTimeout, r.err),
				fmt.Sprintf("the catch-up of this tenant's silo schema is slow (a large silo, or a lock held by a migration); it is retried every recheck interval — raise PROBECTL_SILO_QUARANTINE_CHECK_TIMEOUT (now %s) if it needs longer", s.checkTimeout))
		case r.err != nil:
			return entry(tenancy.QuarantineSchemaCatchUpFailed, "silo schema catch-up: "+r.err.Error(), "")
		}
	}
	if siloCaughtUp(t) {
		if e := s.schemaComplete(ctx, t); e != nil {
			return e
		}
	}
	if !s.readerScoped {
		return nil
	}
	if s.readerGap != nil && t.Residency != "" {
		if err := s.readerGap(t.Residency); err != nil {
			return entry(tenancy.QuarantineReaderCredentialMissing, err.Error(), "")
		}
	}
	if d, ok := down[t.Residency]; ok {
		return entry(d.Reason, d.Detail, d.Remedy)
	}
	r := s.bounded(ctx, func(ctx context.Context) error { return s.checks.CatchUpReaderScope(ctx, t.ID, t.Residency) })
	switch {
	case r.err == nil:
		return nil
	case r.timedOut:
		return entry(tenancy.QuarantineReaderScopeUnproven,
			fmt.Sprintf("the reader-scope proof did not finish within %s: %v", s.checkTimeout, r.err),
			fmt.Sprintf("the proof for this tenant was slow — usually another replica holding its reader-scope lock during a rollout, or a slow %s; it is retried every recheck interval — raise PROBECTL_SILO_QUARANTINE_CHECK_TIMEOUT (now %s) if it needs longer", planeLabel(t.Residency), s.checkTimeout))
	case planeUnreachable(r.err):
		e := entry(tenancy.QuarantinePlaneUnreachable, "reader-scope proof could not reach the plane: "+r.err.Error(), "")
		if planeRefused(r.err) {
			down[t.Residency] = *e
		}
		return e
	default:
		return entry(tenancy.QuarantineReaderScopeUnproven, "reader-scope proof: "+r.err.Error(), "")
	}
}

// siloCaughtUp: the siloed tenants whose schemas the catch-up keeps current
// (active and suspended), and so the ones verified complete. An offboarding
// silo is not caught up; InTenant's per-transaction table guard still
// refuses it if it lacks a table.
func siloCaughtUp(t IsolatedTenant) bool {
	return t.Model == string(tenancy.IsolationSiloed) && (t.Status == "active" || t.Status == "suspended")
}

// schemaComplete verifies a siloed tenant's schema carries every tenant-owned
// table (DPR-385).
func (s *QuarantineSupervisor) schemaComplete(ctx context.Context, t IsolatedTenant) *tenancy.QuarantineEntry {
	var missing map[string][]string
	r := s.bounded(ctx, func(ctx context.Context) error {
		var err error
		missing, err = s.checks.MissingSiloTables(ctx, []string{t.ID})
		return err
	})
	if r.err != nil {
		return &tenancy.QuarantineEntry{TenantID: t.ID, Reason: tenancy.QuarantineSchemaIncomplete, Plane: t.Residency,
			Detail: "could not verify the silo schema's tables: " + r.err.Error(), Remedy: incompleteRemedy(t.ID, nil)}
	}
	return incompleteEntry(t, missing[t.ID])
}

func incompleteEntry(t IsolatedTenant, missing []string) *tenancy.QuarantineEntry {
	if len(missing) == 0 {
		return nil
	}
	return &tenancy.QuarantineEntry{TenantID: t.ID, Reason: tenancy.QuarantineSchemaIncomplete, Plane: t.Residency,
		Detail: fmt.Sprintf("silo schema %s lacks the tenant-owned table(s) %s, which every silo must carry; without the guard they would resolve to the pooled public tables (DPR-385)",
			SchemaName(t.ID), strings.Join(missing, ", ")),
		Remedy: incompleteRemedy(t.ID, missing)}
}

func incompleteRemedy(tenantID string, missing []string) string {
	what := "the missing tables"
	if len(missing) > 0 {
		what = strings.Join(missing, ", ")
	}
	return fmt.Sprintf("restore %s in schema %s (for example from backup), or roll the control plane: its startup catch-up recreates missing tables EMPTY. The supervisor never recreates them silently; it re-verifies every recheck interval and releases the tenant once the schema is complete", what, SchemaName(tenantID))
}

// planeUnreachable reports a transport-level failure (refused, DNS, TLS
// handshake, the HTTP client's own timeout, an open circuit breaker) as
// opposed to a plane that answered and refused the proof.
func planeUnreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false // a budget or a shutdown, never a verdict on the plane (DPR-380)
	}
	var urlErr *url.Error
	var netErr net.Error
	return errors.Is(err, breaker.ErrOpen) || errors.As(err, &urlErr) || errors.As(err, &netErr)
}

// planeRefused is the subset that condemns the whole plane for this pass: a
// connection that could not be opened at all, or an open breaker. A timeout
// is never memoized — it can be one tenant's slow query or lock wait.
func planeRefused(err error) bool {
	if errors.Is(err, breaker.ErrOpen) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" && !op.Timeout() {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
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
		return fmt.Sprintf("add %s=https://<clickhouse-host>:<port> back to PROBECTL_DATAPLANES (with its PROBECTL_DATAPLANE_BASIC_AUTH_FILES and PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES entries) and roll the control plane (a configuration fault clears only with a rolling restart, D-66); the tenant is released on each replica that starts with the plane configured", plane)
	case tenancy.QuarantinePlaneUnreachable:
		return fmt.Sprintf("restore connectivity from the control plane to %s's ClickHouse (DNS, TLS trust, firewall, server health); the supervisor re-proves the reader scope every recheck interval and releases the tenant without a restart", planeLabel(plane))
	case tenancy.QuarantineReaderCredentialMissing:
		return fmt.Sprintf("add %s=/abs/path/reader-credential.json (the reader login's credential on that plane) to PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES and roll the control plane (a configuration fault clears only with a rolling restart, D-66; DPR-327)", plane)
	case tenancy.QuarantineReaderScopeUnproven:
		return fmt.Sprintf("on %s's ClickHouse grant the control login SELECT ON *.* WITH GRANT OPTION and keep the reader a SQL-created, SELECT-only login (docs/lifecycle.md, 0.6.6); the supervisor re-installs and re-proves the scope and releases the tenant without a restart", planeLabel(plane))
	case tenancy.QuarantineSchemaCatchUpFailed:
		return "fix the precondition the catch-up statement names (usually PROBECTL_MIGRATE_DATABASE_URL, the migration login's privileges, or a hand-edited or missing silo schema); the supervisor retries the catch-up and releases the tenant without a restart"
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
// that pass (or are no longer routed as siloed/hybrid), and persists and
// audits the transitions.
//
// It also verifies, every interval, that each siloed tenant that is NOT
// quarantined still has every tenant-owned table in its schema (DPR-385),
// and quarantines one that lost a table.
func (s *QuarantineSupervisor) Recheck(ctx context.Context) {
	held := s.registry.List()
	tenants, err := s.list(ctx)
	switch {
	case err != nil:
		s.log.Warn("silo quarantine: recheck could not read the tenant registry; keeping every quarantine", "error", err.Error())
	default:
		if len(held) > 0 {
			s.recheckHeld(ctx, held, tenants)
		}
		s.verifyHealthySilos(ctx, tenants)
	}
	s.flush(ctx)
}

// verifyHealthySilos quarantines each routed siloed tenant whose schema lost
// a tenant-owned table since it was proven (DPR-385). One catalog query.
func (s *QuarantineSupervisor) verifyHealthySilos(ctx context.Context, tenants []IsolatedTenant) {
	var ids []string
	byID := map[string]IsolatedTenant{}
	for _, t := range tenants {
		if !siloCaughtUp(t) || s.registry.Check(t.ID) != nil {
			continue
		}
		ids = append(ids, t.ID)
		byID[t.ID] = t
	}
	if len(ids) == 0 || ctx.Err() != nil {
		return
	}
	var missing map[string][]string
	r := s.bounded(ctx, func(ctx context.Context) error {
		var err error
		missing, err = s.checks.MissingSiloTables(ctx, ids)
		return err
	})
	if r.err != nil {
		s.log.Warn("silo quarantine: could not verify the silo schemas this interval", "error", r.err.Error())
		return
	}
	for id, tables := range missing {
		if t, ok := byID[id]; ok {
			if e := incompleteEntry(t, tables); e != nil {
				s.enter(*e)
			}
		}
	}
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
			// isolated target any more. An erased tenant has no chain left.
			s.release(e, "the tenant is no longer an isolated (siloed/hybrid) tenant that is routed", true)
			continue
		}
		// An incomplete silo is never repaired behind the operator's back.
		next := s.evaluate(ctx, t, down, e.Reason != tenancy.QuarantineSchemaIncomplete)
		if ctx.Err() != nil {
			return // shutting down: never release on a canceled check
		}
		if next == nil {
			s.release(e, "every startup check passes again", false)
			continue
		}
		s.enter(*next) // refresh the cause (Since is kept)
	}
}

// flush persists this replica's holds and releases, prunes replicas that are
// gone, and writes the tenant-chain receipts of the transitions that made.
// Anything that fails is retried on the next recheck.
func (s *QuarantineSupervisor) flush(ctx context.Context) {
	live := s.live()
	heldIDs := map[string]bool{}
	for _, e := range s.registry.List() {
		heldIDs[e.TenantID] = true
		entered, err := s.store.hold(ctx, s.replica, e, live)
		if err != nil {
			s.log.Warn("silo quarantine: could not persist the quarantine; retrying", "tenant", e.TenantID, "error", err.Error())
			continue
		}
		if entered {
			s.queueNotice(&tenantNotice{entry: e, entered: true})
		}
	}
	// Rows a previous process on this replica identity left for tenants it
	// no longer holds: their release was never persisted.
	if leftover, err := s.store.mine(ctx, s.replica); err == nil {
		s.mu.Lock()
		for _, e := range leftover {
			if _, pending := s.drops[e.TenantID]; !heldIDs[e.TenantID] && !pending {
				s.drops[e.TenantID] = pendingDrop{entry: e, why: "every startup check passes again (on this replica's restart)"}
			}
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	drops := make([]pendingDrop, 0, len(s.drops))
	for _, d := range s.drops {
		drops = append(drops, d)
	}
	s.mu.Unlock()
	for _, d := range drops {
		released, err := s.store.drop(ctx, s.replica, d.entry, live, d.why)
		if err != nil {
			s.log.Warn("silo quarantine: could not persist the release; retrying", "tenant", d.entry.TenantID, "error", err.Error())
			continue
		}
		s.mu.Lock()
		delete(s.drops, d.entry.TenantID)
		s.mu.Unlock()
		if released {
			s.queueNotice(&tenantNotice{entry: d.entry, providerOnly: d.providerOnly})
		}
	}
	if gone, err := s.store.prune(ctx, live); err != nil {
		s.log.Warn("silo quarantine: provider view prune failed", "error", err.Error())
	} else {
		for _, e := range gone {
			s.queueNotice(&tenantNotice{entry: e})
		}
	}
	s.flushNotices(ctx)
}

func (s *QuarantineSupervisor) queueNotice(n *tenantNotice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices = append(s.notices, n)
}

// flushNotices writes the pending tenant-chain receipts. One that cannot
// land — the silo schema is missing (it is never written to the pooled
// table, DPR-368), the tenant is erased, or the bounded retries ran out — is
// recorded on the provider stream only, and the given-up ones are counted.
func (s *QuarantineSupervisor) flushNotices(ctx context.Context) {
	s.mu.Lock()
	pending := s.notices
	s.notices = nil
	s.mu.Unlock()
	var keep []*tenantNotice
	for _, n := range pending {
		why := ""
		switch {
		case n.providerOnly:
			why = "the tenant is no longer routed (erased or no longer isolated); it has no chain to write to"
		default:
			err := s.tenant(ctx, *n)
			if err == nil {
				continue
			}
			n.attempts++
			switch {
			case errors.Is(err, tenancy.ErrSiloSchemaMissing):
				why = "the tenant's silo schema is missing or has no audit table: " + tenancy.RedactQuarantineDetail(err.Error())
			case n.attempts >= maxNoticeAttempts:
				why = fmt.Sprintf("gave up after %d attempts: %s", n.attempts, tenancy.RedactQuarantineDetail(err.Error()))
				s.registry.NoteNoticeDropped()
			default:
				s.log.Warn("silo quarantine: tenant-chain receipt failed; retrying", "tenant", n.entry.TenantID,
					"attempt", n.attempts, "error", err.Error())
				keep = append(keep, n)
				continue
			}
		}
		if err := s.store.record(ctx, AuditQuarantineNoticeProviderOnly, n.entry.TenantID, map[string]any{
			"transition": n.action(), "reason": string(n.entry.Reason), "plane": n.entry.Plane,
			"replica": s.replica, "why": why, "decision": "D-62",
		}); err != nil {
			keep = append(keep, n)
			continue
		}
		s.log.Warn("silo quarantine: tenant-chain receipt recorded on the provider stream only", "tenant", n.entry.TenantID, "why", why)
	}
	if len(keep) > 0 {
		s.mu.Lock()
		s.notices = append(keep, s.notices...)
		s.mu.Unlock()
	}
}

// appendTenantNotice writes the transition to the tenant's own audit chain:
// the reason, plane and replica, never the operator-side detail. A silo
// without its audit table is refused by InTenant (ErrSiloSchemaMissing),
// never written to the pooled table.
func (s *QuarantineSupervisor) appendTenantNotice(ctx context.Context, n tenantNotice) error {
	e := n.entry
	data := map[string]any{"reason": string(e.Reason), "plane": e.Plane, "since": e.Since.UTC().Format(time.RFC3339),
		"replica": s.replica, "decision": "D-62"}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(e.TenantID))
	return tenancy.InTenantQuarantineNotice(tctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, QuarantineActor, n.action(), e.TenantID, data)
		return err
	})
}
