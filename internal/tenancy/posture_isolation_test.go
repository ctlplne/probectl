// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build isolation

package tenancy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TENANT-104: the boot self-check passes against a correctly-migrated database
// (probectl_app is non-super, non-bypassrls; every tenant table FORCEs RLS).
func TestAssertIsolationPosturePasses(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture check must pass on a migrated DB: %v", err)
	}
}

// The app role is provably non-bypassrls + non-super (the migration's promise,
// verified through the same role the runtime assumes).
func TestAppRoleCannotBypassRLS(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}
	var super, bypass bool
	if err := tx.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if super || bypass {
		t.Fatalf("app role must be non-super non-bypassrls, got super=%t bypass=%t", super, bypass)
	}
}

// TENANT-104: the check is not vacuous — if a tenant table loses FORCE RLS,
// the posture assertion FAILS (we toggle it inside a rolled-back tx so the
// database is never left weakened).
func TestAssertIsolationPostureCatchesUnforcedRLS(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// Disable FORCE on one tenant table within a transaction, run the check on
	// that same connection, then roll back. Using a single dedicated conn keeps
	// the DDL visible to the check and the rollback total.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "ALTER TABLE tests NO FORCE ROW LEVEL SECURITY"); err != nil {
		t.Fatalf("toggle force off: %v", err)
	}
	// Assume the app role within this SAME tx (reversible at rollback) and run
	// the real check core against this connection's view — it must reject the
	// unforced table. This proves the check is not vacuous.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}
	if err := tenancy.AssertPostureTx(ctx, tx); err == nil || !strings.Contains(err.Error(), "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("posture check must reject an unforced tenant table, got %v", err)
	}
}

// TENANT-008: the boot self-check must also scan SILOED per-tenant schemas, not
// just public. We create a per-tenant schema with a tenant_id table whose RLS
// is ENABLED but NOT FORCED — the exact silo blind spot — and assert the
// posture check catches it and names the schema-qualified offender. All inside
// a rolled-back tx so the database is never left weakened.
func TestAssertIsolationPostureCoversSiloedSchema(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const schema = "t_isoposture"
	for _, ddl := range []string{
		`CREATE SCHEMA IF NOT EXISTS ` + schema,
		`CREATE TABLE ` + schema + `.probes (tenant_id uuid NOT NULL, name text)`,
		// RLS enabled but deliberately NOT forced — the silo blind spot.
		`ALTER TABLE ` + schema + `.probes ENABLE ROW LEVEL SECURITY`,
	} {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			t.Fatalf("provision silo schema (%s): %v", ddl, err)
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}
	err = tenancy.AssertPostureTx(ctx, tx)
	if err == nil {
		t.Fatal("posture check passed despite an unforced tenant table in a SILOED schema (TENANT-008 blind spot)")
	}
	if !strings.Contains(err.Error(), "FORCE ROW LEVEL SECURITY") || !strings.Contains(err.Error(), schema+".probes") {
		t.Fatalf("posture error must name the schema-qualified silo offender, got %v", err)
	}
}

// TENANT-cff7c9e6: policy semantics are a storage boundary, not a keyword
// convention. These two valid PostgreSQL policies evade a lexical "contains
// tenant_id" check while exposing both tenant fixtures either when the GUC is
// unset or whenever any tenant is selected. Each mutation lives in a rolled-back
// transaction; the real boot posture must identify the policy and refuse start.
func TestAssertIsolationPostureRejectsAlternateFailOpenPolicies(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	fixture := seedPreTenantAuthFixture(ctx, t, pool)

	tests := []struct {
		name       string
		expression string
		tenantGUC  string
	}{
		{
			name:       "unset GUC coalesces to each row tenant",
			expression: `tenant_id = COALESCE(NULLIF(current_setting('probectl.tenant_id', true), '')::uuid, tenant_id)`,
		},
		{
			name:       "any set GUC enables row tautology",
			expression: `tenant_id = tenant_id AND current_setting('probectl.tenant_id', true) IS NOT NULL`,
			tenantGUC:  fixture.tenantA,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Release()

			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			if _, err := tx.Exec(ctx, `DROP POLICY tenant_isolation ON mcp_tokens`); err != nil {
				t.Fatalf("drop strict policy: %v", err)
			}
			if _, err := tx.Exec(ctx,
				`CREATE POLICY tenant_isolation ON mcp_tokens
				   FOR ALL TO probectl_app
				   USING (`+tc.expression+`)
				   WITH CHECK (`+tc.expression+`)`); err != nil {
				t.Fatalf("install unsafe policy fixture: %v", err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
				t.Fatalf("assume app role: %v", err)
			}
			if tc.tenantGUC != "" {
				if _, err := tx.Exec(ctx,
					`SELECT set_config('probectl.tenant_id', $1, true)`, tc.tenantGUC); err != nil {
					t.Fatalf("set tenant GUC: %v", err)
				}
			}

			// Prove this is not a cosmetic alternate spelling: the injected
			// policy exposes both tenants' token rows to one app-role query.
			var visible int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM mcp_tokens
				  WHERE tenant_id IN ($1::uuid, $2::uuid)`,
				fixture.tenantA, fixture.tenantB).Scan(&visible); err != nil {
				t.Fatalf("probe unsafe policy: %v", err)
			}
			if visible != 2 {
				t.Fatalf("unsafe policy fixture exposed %d tenant rows, want 2 to prove regression reachability", visible)
			}

			err = tenancy.AssertPostureTx(ctx, tx)
			if err == nil || !strings.Contains(err.Error(), "non-strict application policies") ||
				!strings.Contains(err.Error(), "mcp_tokens.tenant_isolation") {
				t.Fatalf("boot posture accepted fail-open two-tenant policy: %v", err)
			}
		})
	}
}
