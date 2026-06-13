// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package silo

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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

// CHPlanes bundles every ClickHouse plane's provisioning seam. A nil field =
// that plane runs the memory store (no per-tenant database leg).
type CHPlanes struct {
	Flows FlowDDL
	Paths PathDDL
	EBPF  EBPFDDL
	Otel  OtelDDL
}

// Provisioner creates, catches up, and tears down per-tenant isolated stores.
// DDL runs as the pool's migration-capable login role (the same role that
// applies migrations — schema creation is a migration-class operation).
type Provisioner struct {
	pool          *pgxpool.Pool
	ch            CHPlanes
	planes        map[string]DataPlane
	retentionDays int
	log           *slog.Logger
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
	return &Provisioner{pool: pool, ch: ch, planes: planes, retentionDays: retentionDays, log: log}
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

// provisionCH creates every configured CH plane's per-tenant database (idempotent).
func (p *Provisioner) provisionCH(ctx context.Context, tenantID, residency string) error {
	if p.ch.Flows != nil {
		if err := p.ch.Flows.EnsureTenantDatabase(ctx, p.flowTarget(tenantID, residency), p.retentionDays); err != nil {
			return fmt.Errorf("silo: provision flow plane: %w", err)
		}
	}
	if p.ch.Paths != nil {
		if err := p.ch.Paths.EnsureTenantDatabase(ctx, p.pathTarget(tenantID, residency), p.retentionDays); err != nil {
			return fmt.Errorf("silo: provision path plane: %w", err)
		}
	}
	if p.ch.EBPF != nil {
		if err := p.ch.EBPF.EnsureTenantDatabase(ctx, p.ebpfTarget(tenantID, residency), p.retentionDays); err != nil {
			return fmt.Errorf("silo: provision ebpf plane: %w", err)
		}
	}
	if p.ch.Otel != nil {
		if err := p.ch.Otel.EnsureTenantDatabase(ctx, p.otelTarget(tenantID, residency), p.retentionDays); err != nil {
			return fmt.Errorf("silo: provision otel plane: %w", err)
		}
	}
	return nil
}

// teardownCH drops every configured CH plane's per-tenant database.
func (p *Provisioner) teardownCH(ctx context.Context, tenantID, residency string) error {
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
	return nil
}

// readCatalog loads the planner's facts from information_schema.
func (p *Provisioner) readCatalog(ctx context.Context, schema string) (Catalog, error) {
	cat := Catalog{Columns: map[string][]Column{}, SchemaColumns: map[string][]Column{}}

	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT table_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND column_name = 'tenant_id'`)
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

	colRows, err := p.pool.Query(ctx, `
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
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("silo: begin ddl tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, stmt := range plan {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("silo: %q: %w", firstLine(stmt), err)
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
	if len(plan) == 0 {
		return nil
	}
	p.log.Info("silo catch-up", "tenant", tenantID, "statements", len(plan))
	return p.execPlan(ctx, plan)
}

// DriftFor reports a siloed tenant's catch-up debt (console honesty).
func (p *Provisioner) DriftFor(ctx context.Context, tenantID string) (Drift, error) {
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
