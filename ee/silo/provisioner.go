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
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// FlowDDL is the ClickHouse side of provisioning the FLOW plane (implemented by
// *flowstore.ClickHouse; nil when the deployment runs the memory flow store).
type FlowDDL interface {
	EnsureTenantDatabase(ctx context.Context, t flowstore.Target, retentionDays int) error
	DropTenantDatabase(ctx context.Context, t flowstore.Target) error
}

// PathDDL / EBPFDDL / OtelDDL are the ClickHouse provisioning seams for the
// remaining three telemetry planes (TENANT-001). Each is implemented by the
// store's *ClickHouse; nil when that plane runs the memory store. Without
// these a siloed tenant got physical isolation for FLOW ONLY — path traces,
// eBPF L7 edges and OTLP spans+logs (highest PII) leaked into the shared
// pooled tables and ignored residency pinning.
type PathDDL interface {
	EnsureTenantDatabase(ctx context.Context, t pathstore.Target, retentionDays int) error
	DropTenantDatabase(ctx context.Context, t pathstore.Target) error
}
type EBPFDDL interface {
	EnsureTenantDatabase(ctx context.Context, t ebpfstore.Target, retentionDays int) error
	DropTenantDatabase(ctx context.Context, t ebpfstore.Target) error
}
type OtelDDL interface {
	EnsureTenantDatabase(ctx context.Context, t otelstore.Target, retentionDays int) error
	DropTenantDatabase(ctx context.Context, t otelstore.Target) error
}
type EndpointDDL interface {
	EnsureTenantDatabase(ctx context.Context, t endpointstore.Target, retentionDays int) error
	DropTenantDatabase(ctx context.Context, t endpointstore.Target) error
}

// ReaderScope (DPR-323) is the reader-login side of a per-tenant ClickHouse
// database: with tenant scoping on, a siloed or hybrid tenant's reads run as
// the least-privilege reader login (chclient.RouteRead), which may read a
// per-tenant table only once it carries the setting-scoped row policy. A
// read misrouted to another tenant's database then returns no row. It is
// implemented by chclient.SiloScope (each scoped store's SiloReaderScope).
type ReaderScope interface {
	// Endpoint names the server a database at baseURL lives on, so stores
	// sharing a server scope it once.
	Endpoint(baseURL string) string
	Ensure(ctx context.Context, baseURL, database string) error
	Verify(ctx context.Context, baseURL, database string) error
	Revoke(ctx context.Context, baseURL, database string) error
}

// CHPlanes bundles every ClickHouse plane's provisioning seam. A nil field =
// that plane runs the memory store (no per-tenant database leg).
type CHPlanes struct {
	Flows    FlowDDL
	Paths    PathDDL
	EBPF     EBPFDDL
	Otel     OtelDDL
	Endpoint EndpointDDL
	// Readers are the tenant-scoped stores' reader scopes (DPR-323). Empty =
	// no store scopes its tenant reads, so none runs as the reader login.
	Readers []ReaderScope
}

// Provisioner creates, catches up, and tears down per-tenant isolated stores.
// DDL runs as the migration-capable login role (the same role that applies
// migrations — schema creation is a migration-class operation): the DDL pool
// when one is attached, since the serve login is least-privilege (TEN-01).
type Provisioner struct {
	pool                  *pgxpool.Pool
	ddl                   *pgxpool.Pool // the migration login; nil = pool
	ch                    CHPlanes
	planes                map[string]DataPlane
	retentionDays         int
	endpointRetentionDays int
	log                   *slog.Logger
	// readerPlaneCheck (DPR-327) reports whether the reader login can reach
	// a residency plane; nil = every plane is assumed reachable.
	readerPlaneCheck func(residency string) error
}

// WithReaderPlaneCheck installs the check that the reader login has a
// credential for a residency plane (DPR-327). It runs before a tenant's reader
// scope is installed or proven on that plane, at provisioning and at the boot
// catch-up, so a plane needs a reader credential exactly when a siloed or
// hybrid tenant lives on it, and the refusal names the missing entry.
func (p *Provisioner) WithReaderPlaneCheck(check func(residency string) error) *Provisioner {
	p.readerPlaneCheck = check
	return p
}

// NewProvisioner wires the silo provisioner across every ClickHouse plane
// (TENANT-001). nil plane fields are skipped (that plane is memory-backed).
func NewProvisioner(pool *pgxpool.Pool, ch CHPlanes, planes map[string]DataPlane, retentionDays int, log *slog.Logger) *Provisioner {
	if log == nil {
		log = slog.Default()
	}
	if planes == nil {
		planes = map[string]DataPlane{}
	}
	return &Provisioner{
		pool: pool, ch: ch, planes: planes, retentionDays: retentionDays,
		endpointRetentionDays: retentionDays, log: log,
	}
}

// WithDDLPool attaches the migration login (PROBECTL_MIGRATE_DATABASE_URL)
// that silo schemas, their catch-up and the pre-tenant backfill run as. The
// least-privilege serve login cannot create a schema.
func (p *Provisioner) WithDDLPool(ddl *pgxpool.Pool) *Provisioner {
	p.ddl = ddl
	return p
}

func (p *Provisioner) ddlPool() *pgxpool.Pool {
	if p.ddl != nil {
		return p.ddl
	}
	return p.pool
}

// ddlError names the missing migration login (tenancy.ErrDDLLoginRequired)
// when the serve login was refused a silo DDL statement.
func (p *Provisioner) ddlError(err error) error {
	var pgErr *pgconn.PgError
	if p.ddl == nil && errors.As(err, &pgErr) && pgErr.Code == "42501" {
		return fmt.Errorf("%w: %w", tenancy.ErrDDLLoginRequired, err)
	}
	return err
}

// WithEndpointRetentionDays keeps endpoint event retention independent from
// the flow-plane TTL while preserving the established constructor.
func (p *Provisioner) WithEndpointRetentionDays(days int) *Provisioner {
	p.endpointRetentionDays = days
	return p
}

// ValidResidency reports whether a residency name is provisionable ("" =
// the default plane, always valid).
func (p *Provisioner) ValidResidency(name string) bool {
	if name == "" {
		return true
	}
	_, ok := p.planes[name]
	return ok
}

// Planes lists the configured residency names.
func (p *Provisioner) Planes() []string { return PlaneNames(p.planes) }

// chBaseURL resolves a tenant's residency ClickHouse endpoint ("" = default).
func (p *Provisioner) chBaseURL(residency string) string {
	if plane, ok := p.planes[residency]; ok {
		return plane.CHURL
	}
	return ""
}

// Per-store targets (the Target types are package-local). All carry the same
// per-tenant database + residency BaseURL (TENANT-001).
func (p *Provisioner) flowTarget(tenantID, residency string) flowstore.Target {
	return flowstore.Target{Database: CHDatabase(tenantID), BaseURL: p.chBaseURL(residency)}
}
func (p *Provisioner) pathTarget(tenantID, residency string) pathstore.Target {
	return pathstore.Target{Database: CHDatabase(tenantID), BaseURL: p.chBaseURL(residency)}
}
func (p *Provisioner) ebpfTarget(tenantID, residency string) ebpfstore.Target {
	return ebpfstore.Target{Database: CHDatabase(tenantID), BaseURL: p.chBaseURL(residency)}
}
func (p *Provisioner) otelTarget(tenantID, residency string) otelstore.Target {
	return otelstore.Target{Database: CHDatabase(tenantID), BaseURL: p.chBaseURL(residency)}
}
func (p *Provisioner) endpointTarget(tenantID, residency string) endpointstore.Target {
	return endpointstore.Target{Database: CHDatabase(tenantID), BaseURL: p.chBaseURL(residency)}
}

// provisionCompensateTimeout bounds the undo of an aborted provision. It runs
// on a detached context, so it needs its own bound.
const provisionCompensateTimeout = 30 * time.Second

// provisionStep is one leg of the ClickHouse provision, with the compensation
// that undoes it. Recording them as a LEDGER (rather than five sequential
// early-returns) is what makes the sequence compensating: a failure at leg N
// undoes legs 1..N-1 instead of leaving their databases orphaned behind an
// abandoned attempt (Foundation-Loop S-fadcec95).
type provisionStep struct {
	plane      string
	ensure     func(context.Context) error
	compensate func(context.Context) error
	// undoOwnFailure: a failed ensure may have done part of its work (a
	// reader scope's first grants), so provisioning compensates it too. The
	// tenant is not routable yet, so withdrawing it can cut off nobody.
	undoOwnFailure bool
}

// chSteps is the ordered ledger of ClickHouse provisioning legs for one
// tenant. Only configured planes appear, so the ledger describes exactly what
// this deployment will do — and exactly what it must undo.
func (p *Provisioner) chSteps(tenantID, residency string) []provisionStep {
	var steps []provisionStep
	if p.ch.Flows != nil {
		t := p.flowTarget(tenantID, residency)
		steps = append(steps, provisionStep{
			plane:      "flow",
			ensure:     func(ctx context.Context) error { return p.ch.Flows.EnsureTenantDatabase(ctx, t, p.retentionDays) },
			compensate: func(ctx context.Context) error { return p.ch.Flows.DropTenantDatabase(ctx, t) },
		})
	}
	if p.ch.Paths != nil {
		t := p.pathTarget(tenantID, residency)
		steps = append(steps, provisionStep{
			plane:      "path",
			ensure:     func(ctx context.Context) error { return p.ch.Paths.EnsureTenantDatabase(ctx, t, p.retentionDays) },
			compensate: func(ctx context.Context) error { return p.ch.Paths.DropTenantDatabase(ctx, t) },
		})
	}
	if p.ch.EBPF != nil {
		t := p.ebpfTarget(tenantID, residency)
		steps = append(steps, provisionStep{
			plane:      "ebpf",
			ensure:     func(ctx context.Context) error { return p.ch.EBPF.EnsureTenantDatabase(ctx, t, p.retentionDays) },
			compensate: func(ctx context.Context) error { return p.ch.EBPF.DropTenantDatabase(ctx, t) },
		})
	}
	if p.ch.Otel != nil {
		t := p.otelTarget(tenantID, residency)
		steps = append(steps, provisionStep{
			plane:      "otel",
			ensure:     func(ctx context.Context) error { return p.ch.Otel.EnsureTenantDatabase(ctx, t, p.retentionDays) },
			compensate: func(ctx context.Context) error { return p.ch.Otel.DropTenantDatabase(ctx, t) },
		})
	}
	if p.ch.Endpoint != nil {
		t := p.endpointTarget(tenantID, residency)
		steps = append(steps, provisionStep{
			plane: "endpoint",
			ensure: func(ctx context.Context) error {
				return p.ch.Endpoint.EnsureTenantDatabase(ctx, t, p.endpointRetentionDays)
			},
			compensate: func(ctx context.Context) error { return p.ch.Endpoint.DropTenantDatabase(ctx, t) },
		})
	}
	return append(steps, p.readerSteps(tenantID, residency)...)
}

// readerSteps are the last provisioning legs (DPR-323): once every plane's
// tables exist, each distinct server's per-tenant database is put under the
// reader row policy, the reader is granted its tables, and the result is
// proven before the tenant is routable. Compensation revokes it.
func (p *Provisioner) readerSteps(tenantID, residency string) []provisionStep {
	base, db := p.chBaseURL(residency), CHDatabase(tenantID)
	var steps []provisionStep
	for _, r := range p.distinctReaders(base) {
		steps = append(steps, provisionStep{
			plane: "reader scope",
			ensure: func(ctx context.Context) error {
				if p.readerPlaneCheck != nil && residency != "" {
					if err := p.readerPlaneCheck(residency); err != nil {
						return err
					}
				}
				return ensureReaderScope(ctx, r, base, db)
			},
			compensate:     func(ctx context.Context) error { return r.Revoke(ctx, base, db) },
			undoOwnFailure: true,
		})
	}
	return steps
}

// ensureReaderScope installs and proves one database's reader scope.
//
// DPR-326: the scope is withdrawn only on a DEFINITIVE unsafe result
// (chclient.ErrReaderUnsafe: foreign rows visible, a write-capable reader,
// the wrong login, too-broad grants). A proof that could not run — a
// transport error, a timeout, this process being canceled at its startup
// probe — leaves the scope in place: the live replicas keep serving the
// tenant, and only this process refuses to start (the error is returned).
// Withdrawing on every failure turned one pod's network blip into an outage
// of that tenant's reads on every pod.
func ensureReaderScope(ctx context.Context, r ReaderScope, base, db string) error {
	err := r.Ensure(ctx, base, db)
	if err == nil {
		err = r.Verify(ctx, base, db)
	}
	if err == nil || !errors.Is(err, chclient.ErrReaderUnsafe) {
		return err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionCompensateTimeout)
	defer cancel()
	if rerr := r.Revoke(rctx, base, db); rerr != nil {
		return errors.Join(err, fmt.Errorf("withdraw the unproven reader scope: %w", rerr))
	}
	return err
}

// distinctReaders keeps one reader scope per ClickHouse server: stores that
// share a server share its per-tenant database.
func (p *Provisioner) distinctReaders(base string) []ReaderScope {
	seen := map[string]bool{}
	var out []ReaderScope
	for _, r := range p.ch.Readers {
		if r == nil || seen[r.Endpoint(base)] {
			continue
		}
		seen[r.Endpoint(base)] = true
		out = append(out, r)
	}
	return out
}

// CatchUpReaderScope (DPR-323) brings an existing siloed or hybrid tenant's
// per-tenant database under the reader scope and proves it: run at startup,
// before the router is published, for every tenant that has one. Silos
// provisioned before DPR-323 gain it here; on later boots it re-proves that
// the reader sees none of the tenant's rows under any other tenant's setting.
//
// A residency no longer configured is scoped where the router now sends that
// tenant (the default plane, like Router.TargetsFor), with a warning.
func (p *Provisioner) CatchUpReaderScope(ctx context.Context, tenantID, residency string) error {
	if !p.ValidResidency(residency) {
		p.log.Warn("silo reader-scope catch-up: tenant residency is not a configured data plane; scoping the plane the router uses",
			"tenant", tenantID, "residency", residency, "dpr", "DPR-323")
	}
	for _, step := range p.readerSteps(tenantID, residency) {
		if err := step.ensure(ctx); err != nil {
			return fmt.Errorf("silo: %s for tenant %s: %w", step.plane, tenantID, err)
		}
	}
	return nil
}

// provisionCH creates every configured CH plane's per-tenant database
// (idempotent) and COMPENSATES on failure: the legs that already succeeded are
// dropped before the error returns, so an abandoned attempt cannot leave
// orphaned per-tenant databases behind it. Compensation runs on a detached
// context so a caller cancellation — the most likely reason a leg failed —
// cannot also prevent the cleanup.
func (p *Provisioner) provisionCH(ctx context.Context, tenantID, residency string) error {
	steps := p.chSteps(tenantID, residency)
	for i, step := range steps {
		if err := step.ensure(ctx); err != nil {
			provisionErr := fmt.Errorf("silo: provision %s plane: %w", step.plane, err)
			done := steps[:i]
			if step.undoOwnFailure {
				done = steps[:i+1]
			}
			if cerr := p.compensate(ctx, done, tenantID); cerr != nil {
				return errors.Join(provisionErr, cerr)
			}
			return provisionErr
		}
	}
	return nil
}

// compensate undoes completed legs in REVERSE order. Every failure to undo is
// reported (joined), never swallowed: an un-droppable database is exactly the
// orphan an operator must be told about.
func (p *Provisioner) compensate(ctx context.Context, done []provisionStep, tenantID string) error {
	if len(done) == 0 {
		return nil
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionCompensateTimeout)
	defer cancel()
	var errs []error
	for i := len(done) - 1; i >= 0; i-- {
		if err := done[i].compensate(cctx); err != nil {
			errs = append(errs, fmt.Errorf("silo: compensate %s plane for tenant %s: %w", done[i].plane, tenantID, err))
		}
	}
	return errors.Join(errs...)
}

// teardownCH drops every configured CH plane's per-tenant database. The
// reader's grants go first (DPR-323), while the tables they name still exist.
func (p *Provisioner) teardownCH(ctx context.Context, tenantID, residency string) error {
	for _, step := range p.readerSteps(tenantID, residency) {
		if err := step.compensate(ctx); err != nil {
			return fmt.Errorf("silo: teardown %s: %w", step.plane, err)
		}
	}
	if p.ch.Flows != nil {
		if err := p.ch.Flows.DropTenantDatabase(ctx, p.flowTarget(tenantID, residency)); err != nil {
			return fmt.Errorf("silo: teardown flow plane: %w", err)
		}
	}
	if p.ch.Paths != nil {
		if err := p.ch.Paths.DropTenantDatabase(ctx, p.pathTarget(tenantID, residency)); err != nil {
			return fmt.Errorf("silo: teardown path plane: %w", err)
		}
	}
	if p.ch.EBPF != nil {
		if err := p.ch.EBPF.DropTenantDatabase(ctx, p.ebpfTarget(tenantID, residency)); err != nil {
			return fmt.Errorf("silo: teardown ebpf plane: %w", err)
		}
	}
	if p.ch.Otel != nil {
		if err := p.ch.Otel.DropTenantDatabase(ctx, p.otelTarget(tenantID, residency)); err != nil {
			return fmt.Errorf("silo: teardown otel plane: %w", err)
		}
	}
	if p.ch.Endpoint != nil {
		if err := p.ch.Endpoint.DropTenantDatabase(ctx, p.endpointTarget(tenantID, residency)); err != nil {
			return fmt.Errorf("silo: teardown endpoint plane: %w", err)
		}
	}
	return nil
}

// readCatalog loads the planner's facts from information_schema.
func (p *Provisioner) readCatalog(ctx context.Context, schema string) (Catalog, error) {
	cat := Catalog{Columns: map[string][]Column{}, SchemaColumns: map[string][]Column{}}

	rows, err := p.ddlPool().Query(ctx, `
		SELECT DISTINCT c.table_name
		  FROM information_schema.columns AS c
		  JOIN information_schema.tables AS t
		    ON t.table_schema = c.table_schema
		   AND t.table_name = c.table_name
		 WHERE c.table_schema = 'public'
		   AND c.column_name = 'tenant_id'
		   AND t.table_type = 'BASE TABLE'`)
	if err != nil {
		return cat, fmt.Errorf("silo: read tenant tables: %w", err)
	}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return cat, err
		}
		cat.TenantTables = append(cat.TenantTables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return cat, err
	}

	colRows, err := p.ddlPool().Query(ctx, `
		SELECT table_schema, table_name, column_name,
		       COALESCE(data_type, ''), is_nullable = 'NO', COALESCE(column_default, '')
		  FROM information_schema.columns
		 WHERE table_schema IN ('public', $1)
		 ORDER BY table_schema, table_name, ordinal_position`, schema)
	if err != nil {
		return cat, fmt.Errorf("silo: read columns: %w", err)
	}
	defer colRows.Close()
	schemaTables := map[string]bool{}
	for colRows.Next() {
		var sch, tab string
		var c Column
		if err := colRows.Scan(&sch, &tab, &c.Name, &c.DataType, &c.NotNull, &c.Default); err != nil {
			return cat, err
		}
		if sch == "public" {
			cat.Columns[tab] = append(cat.Columns[tab], c)
		} else {
			cat.SchemaColumns[tab] = append(cat.SchemaColumns[tab], c)
			schemaTables[tab] = true
		}
	}
	for t := range schemaTables {
		cat.SchemaTables = append(cat.SchemaTables, t)
	}
	return cat, colRows.Err()
}

// execPlan runs an ordered DDL plan in one transaction.
func (p *Provisioner) execPlan(ctx context.Context, plan []string) error {
	tx, err := p.ddlPool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("silo: begin ddl tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, stmt := range plan {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("silo: %q: %w", firstLine(stmt), p.ddlError(err))
		}
	}
	return tx.Commit(ctx)
}

// Provision creates a tenant's isolated stores per its model. Idempotent —
// re-running completes a partial provision (also the catch-up entry point).
//   - siloed: Postgres schema + ClickHouse database (+ residency plane)
//   - hybrid: ClickHouse database (+ residency plane) only — control/config
//     state stays pooled by design
func (p *Provisioner) Provision(ctx context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	if !p.ValidResidency(residency) {
		return fmt.Errorf("silo: unknown residency %q (configured: %s)", residency, strings.Join(p.Planes(), ", "))
	}
	switch model {
	case tenancy.IsolationSiloed:
		cat, err := p.readCatalog(ctx, SchemaName(tenantID))
		if err != nil {
			return err
		}
		if err := p.execPlan(ctx, ProvisionPlan(SchemaName(tenantID), cat.TenantTables)); err != nil {
			return err
		}
	case tenancy.IsolationHybrid:
		// no Postgres leg
	default:
		return nil // pooled: nothing to provision
	}
	// TENANT-001: provision EVERY ClickHouse plane's per-tenant database, not
	// just flow — so path/eBPF/otel are physically separated + residency-pinned.
	if err := p.provisionCH(ctx, tenantID, residency); err != nil {
		return err
	}
	p.log.Info("silo provisioned", "tenant", tenantID, "model", string(model), "residency", residency)
	return nil
}

// CatchUp brings a siloed tenant's schema up to the current public shape
// (new tables/columns from later migrations). Run at startup for every
// siloed tenant and on demand from the provider console.
func (p *Provisioner) CatchUp(ctx context.Context, tenantID string) error {
	schema := SchemaName(tenantID)
	cat, err := p.readCatalog(ctx, schema)
	if err != nil {
		return err
	}
	plan := CatchUpPlan(schema, cat)
	if len(plan) > 0 {
		p.log.Info("silo catch-up", "tenant", tenantID, "statements", len(plan))
		if err := p.execPlan(ctx, plan); err != nil {
			return err
		}
	}
	// A restored/pre-0073 silo can have current detailed rows but no public
	// hash locator or certificate-revocation metadata. Rebuild only those
	// opaque fields after the schema columns are current; credential/session
	// PII never leaves the silo.
	return p.backfillPreTenantMetadata(ctx, tenantID, schema)
}

func (p *Provisioner) backfillPreTenantMetadata(
	ctx context.Context,
	tenantID, schema string,
) error {
	tx, err := p.ddlPool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("silo: begin pre-tenant metadata backfill: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := quoteIdent(schema)
	statements := []string{
		`INSERT INTO public.credential_locators
		     (credential_kind, credential_id, token_hash, tenant_id, replaced_at)
		 SELECT 'session', id, token_hash, tenant_id, replaced_at
		   FROM ` + q + `.sessions
		  WHERE tenant_id = $1
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO public.credential_locators
		     (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
		 SELECT 'mcp', id, token_hash, tenant_id, revoked_at
		   FROM ` + q + `.mcp_tokens
		  WHERE tenant_id = $1
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO public.credential_locators
		     (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
		 SELECT 'scim', id, token_hash, tenant_id, revoked_at
		   FROM ` + q + `.scim_tokens
		  WHERE tenant_id = $1
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO public.credential_locators
		     (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
		 SELECT 'otlp', id, token_hash, tenant_id, revoked_at
		   FROM ` + q + `.otlp_tokens
		  WHERE tenant_id = $1
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO public.credential_locators
		     (credential_kind, credential_id, token_hash, tenant_id,
		      revoked_at, consumed_at)
		 SELECT 'agent_enroll', id, token_hash, tenant_id, revoked_at, used_at
		   FROM ` + q + `.agent_enroll_tokens
		  WHERE tenant_id = $1
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO public.agent_identity_revocations
		     (tenant_id, agent_id, spiffe_id, serial, not_after,
		      revoked_at, revoked_by)
		 SELECT tenant_id, agent_id, spiffe_id, serial, not_after,
		        revoked_at, revoked_by
		   FROM ` + q + `.agent_identities
		  WHERE tenant_id = $1 AND revoked_at IS NOT NULL
		 ON CONFLICT DO NOTHING`,
	}
	for _, stmt := range statements {
		if _, err := tx.Exec(ctx, stmt, tenantID); err != nil {
			return fmt.Errorf(
				"silo: backfill pre-tenant metadata from %s: %w",
				schema, err,
			)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("silo: commit pre-tenant metadata backfill: %w", err)
	}
	return nil
}

// driftFor reports a siloed tenant's catch-up debt (console honesty).
func (p *Provisioner) driftFor(ctx context.Context, tenantID string) (Drift, error) {
	cat, err := p.readCatalog(ctx, SchemaName(tenantID))
	if err != nil {
		return Drift{}, err
	}
	return DiffDrift(cat), nil
}

// Teardown removes a tenant's isolated stores (offboard). Idempotent: every
// statement is IF EXISTS, so a failed teardown is safely re-run. Pooled rows
// (hybrid control state) are NOT touched here — verifiable deletion of
// pooled data is the S-T5 compliance flow.
func (p *Provisioner) Teardown(ctx context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	if model == tenancy.IsolationSiloed {
		if err := p.execPlan(ctx, TeardownPlan(SchemaName(tenantID))); err != nil {
			return err
		}
	}
	if model == tenancy.IsolationSiloed || model == tenancy.IsolationHybrid {
		// TENANT-001: tear down every CH plane's per-tenant database.
		if err := p.teardownCH(ctx, tenantID, residency); err != nil {
			return err
		}
	}
	p.log.Info("silo torn down", "tenant", tenantID, "model", string(model))
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
