// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenancy

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TENANT-104: pooled tenant isolation is enforced at the storage layer by
// Postgres RLS — but RLS is only a boundary if the role the app actually runs
// as cannot bypass it AND every tenant-owned table FORCES row security (so the
// table OWNER is bound too). migrations/0007 creates probectl_app as
// NOLOGIN NOSUPERUSER NOBYPASSRLS, but nothing verified that the role the app
// ASSUMES at runtime (after SET LOCAL ROLE probectl_app) is actually that
// role and is actually constrained. This self-check runs at boot and FATALs
// the control plane if the posture is wrong — a misconfigured deployment must
// never serve traffic with RLS silently off (guardrail 1, fail closed).

// AssertIsolationPosture verifies, inside a real AppRole-scoped transaction,
// that the effective role is non-superuser and cannot bypass RLS, and that
// every tenant-owned table (one carrying a tenant_id column) has FORCE ROW
// LEVEL SECURITY. It returns a non-nil error describing the first violation;
// the caller (main) treats that as fatal.
func AssertIsolationPosture(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("isolation posture: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Assume the same restricted role InTenant uses, so the check reflects the
	// ACTUAL runtime posture, not the connection's login role.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{AppRole}.Sanitize()); err != nil {
		return fmt.Errorf("isolation posture: cannot assume %s (is the role provisioned? migrations/0007): %w", AppRole, err)
	}
	return AssertPostureTx(ctx, tx)
}

// postureQuerier is the minimal surface AssertPostureTx needs (a pgx tx).
type postureQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// AssertPostureTx runs the role + FORCE-RLS checks on an already-role-scoped
// querier. AssertIsolationPosture wraps it (begin + SET ROLE); the isolation
// test suite calls it directly to prove the check is not vacuous.
func AssertPostureTx(ctx context.Context, q postureQuerier) error {
	// 1. The effective role must be non-super, non-bypassrls. current_user is
	// the assumed role after SET LOCAL ROLE.
	var roleName string
	var isSuper, canBypass bool
	if err := q.QueryRow(ctx,
		`SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&roleName, &isSuper, &canBypass); err != nil {
		return fmt.Errorf("isolation posture: read effective role: %w", err)
	}
	if isSuper {
		return fmt.Errorf("isolation posture: the app role %q is a SUPERUSER — RLS is bypassed; tenant isolation is OFF (refusing to start)", roleName)
	}
	if canBypass {
		return fmt.Errorf("isolation posture: the app role %q has BYPASSRLS — tenant isolation is OFF (refusing to start)", roleName)
	}

	// 2. Every tenant-owned table (has a tenant_id column) must FORCE row
	// security — otherwise the table owner (and any future grant) reads across
	// tenants. relforcerowsecurity catches the subtle case the audit named: RLS
	// enabled but not forced.
	//
	// TENANT-008: this scans EVERY non-system schema, not just public. Siloed
	// tenants' tables live in per-tenant schemas (ee/silo provisions them with
	// ENABLE+FORCE RLS); the boot guard must inspect those too, so a
	// partially-provisioned or hand-edited silo schema with RLS enabled-but-not-
	// forced can never pass boot. We report schema.table so an offender in a
	// silo schema is identifiable.
	rows, err := q.Query(ctx, `
		SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'
		  AND EXISTS (
		      SELECT 1 FROM pg_attribute a
		      WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		  )`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate tenant tables: %w", err)
	}
	defer rows.Close()

	var offenders []string
	var checked int
	for rows.Next() {
		var schema, name string
		var enabled, forced bool
		if err := rows.Scan(&schema, &name, &enabled, &forced); err != nil {
			return fmt.Errorf("isolation posture: scan: %w", err)
		}
		checked++
		if !enabled || !forced {
			offenders = append(offenders, fmt.Sprintf("%s.%s(rls=%t,force=%t)", schema, name, enabled, forced))
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate: %w", err)
	}
	if checked == 0 {
		return fmt.Errorf("isolation posture: found NO tenant-owned tables to verify — migrations not applied? (refusing to start)")
	}
	if len(offenders) > 0 {
		return fmt.Errorf("isolation posture: %d tenant table(s) without FORCE ROW LEVEL SECURITY: %s (refusing to start)",
			len(offenders), strings.Join(offenders, ", "))
	}
	return nil
}

// profileCountQuerier is the minimal surface AssertDeploymentProfilePosture
// needs (a pgxpool.Pool satisfies it; the unit test passes a fake).
type profileCountQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// AssertDeploymentProfilePosture (RED-001) fails closed at boot when the control
// plane is running the single-tenant profile — which leaves ClickHouse
// row-policies AND the bus strict-lane OFF by default (chScopeDefault=false in
// config) — but Postgres actually holds more than one tenant. Postgres-resident
// data stays isolated by always-on FORCE-RLS (AssertIsolationPosture above), but
// the high-cardinality CH planes (flow/eBPF/path/threat) would serve many
// tenants with their storage-layer tenant scoping degraded. An MSP that forgets
// PROBECTL_DEPLOYMENT_PROFILE must not silently serve multiple tenants with that
// defense-in-depth off (guardrail 1, fail closed). If the operator has
// explicitly enabled CH tenant scoping (chTenantScoped), the posture is not
// degraded and the check is a no-op.
func AssertDeploymentProfilePosture(ctx context.Context, q profileCountQuerier, profile string, chTenantScoped bool) error {
	if profile != "single" || chTenantScoped {
		return nil
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err != nil {
		return fmt.Errorf("profile posture: count tenants: %w", err)
	}
	if n > 1 {
		return fmt.Errorf("deployment posture: PROBECTL_DEPLOYMENT_PROFILE=single leaves ClickHouse "+
			"row-policies and the bus strict-lane OFF, but Postgres holds %d tenants — set "+
			"PROBECTL_DEPLOYMENT_PROFILE=multi-tenant (or regulated), or enable PROBECTL_*_TENANT_SCOPING, "+
			"before serving multiple tenants (refusing to start; RED-001, fail closed)", n)
	}
	return nil
}
