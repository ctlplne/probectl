// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// TestCatchUpAuditRLSIsolationAcrossQualifiedSiloReads starts from two restored
// silos whose audit table boundary has drifted completely open. CatchUp must
// restore the catalog controls and make even schema-qualified reads obey the
// caller's tenant GUC. This is the defense behind the router, not a handler
// predicate.
func TestCatchUpAuditRLSIsolationAcrossQualifiedSiloReads(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)

	tenantA := mkTenant(t, pool, "catchup-audit-a-"+stamp, "siloed", "")
	tenantB := mkTenant(t, pool, "catchup-audit-b-"+stamp, "siloed", "")
	tenants := []string{tenantA, tenantB}
	for _, tenantID := range tenants {
		if err := provisioner.Provision(
			ctx,
			tenantID,
			"",
			tenancy.IsolationSiloed,
		); err != nil {
			t.Fatalf("provision silo %s: %v", tenantID, err)
		}
	}
	t.Cleanup(func() {
		for _, tenantID := range tenants {
			if err := provisioner.Teardown(
				context.Background(),
				tenantID,
				"",
				tenancy.IsolationSiloed,
			); err != nil {
				t.Errorf("cleanup silo %s: %v", tenantID, err)
			}
		}
	})

	for i, tenantID := range tenants {
		schema := SchemaName(tenantID)
		table := quoteIdent(schema) + `."audit_events"`
		if _, err := pool.Exec(
			ctx,
			`INSERT INTO `+table+`
			    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
			 VALUES ($1::uuid, 1, 'catchup-test', 'seed', $2,
			         '{}'::jsonb, '', $3)`,
			tenantID,
			fmt.Sprintf("tenant-%d", i),
			fmt.Sprintf("tenant-%d-hash", i),
		); err != nil {
			t.Fatalf("seed silo audit stream %s: %v", tenantID, err)
		}

		// Model a restored/pre-repair table: RLS is disabled, its policy is
		// permissive, the app can delete, and provider maintenance is absent.
		for _, stmt := range []string{
			"ALTER TABLE " + table + " DISABLE ROW LEVEL SECURITY",
			"DROP POLICY IF EXISTS tenant_isolation ON " + table,
			"CREATE POLICY tenant_isolation ON " + table +
				" USING (true) WITH CHECK (true)",
			"GRANT UPDATE, DELETE ON " + table + " TO probectl_app",
			"REVOKE ALL ON " + table + " FROM probectl_provider",
		} {
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("prepare restored silo %s with %q: %v", tenantID, stmt, err)
			}
		}
	}

	// The setup truly represents the fail-before state: tenant A can read the
	// row in tenant B's physical schema when it qualifies that table directly.
	if got := qualifiedAuditCountAsApp(
		ctx,
		t,
		pool,
		SchemaName(tenantB),
		tenantA,
	); got != 1 {
		t.Fatalf("open restored silo precondition count = %d, want 1", got)
	}

	for _, tenantID := range tenants {
		if err := provisioner.CatchUp(ctx, tenantID); err != nil {
			t.Fatalf("catch up restored silo %s: %v", tenantID, err)
		}
		// The repair itself is idempotent.
		if err := provisioner.CatchUp(ctx, tenantID); err != nil {
			t.Fatalf("repeat catch up restored silo %s: %v", tenantID, err)
		}
		assertAuditCatchUpCatalog(t, pool, SchemaName(tenantID))
	}

	for _, tc := range []struct {
		name        string
		schema      string
		caller      string
		wantVisible int
	}{
		{name: "tenant A own silo", schema: SchemaName(tenantA), caller: tenantA, wantVisible: 1},
		{name: "tenant A cannot qualify tenant B silo", schema: SchemaName(tenantB), caller: tenantA, wantVisible: 0},
		{name: "tenant B own silo", schema: SchemaName(tenantB), caller: tenantB, wantVisible: 1},
		{name: "tenant B cannot qualify tenant A silo", schema: SchemaName(tenantA), caller: tenantB, wantVisible: 0},
		{name: "unset tenant fails closed in silo A", schema: SchemaName(tenantA), caller: "", wantVisible: 0},
		{name: "unset tenant fails closed in silo B", schema: SchemaName(tenantB), caller: "", wantVisible: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifiedAuditCountAsApp(
				ctx,
				t,
				pool,
				tc.schema,
				tc.caller,
			); got != tc.wantVisible {
				t.Fatalf(
					"schema-qualified visible rows = %d, want %d",
					got,
					tc.wantVisible,
				)
			}
		})
	}
}

func assertAuditCatchUpCatalog(
	t *testing.T,
	pool *pgxpool.Pool,
	schema string,
) {
	t.Helper()

	var (
		rlsEnabled     bool
		rlsForced      bool
		permissive     bool
		allCommands    bool
		publicPolicy   bool
		qual           string
		withCheck      string
		providerUsage  bool
		providerSelect bool
		providerDelete bool
		providerUpdate bool
		appSelect      bool
		appInsert      bool
		appDelete      bool
	)
	if err := pool.QueryRow(context.Background(), `
SELECT c.relrowsecurity,
       c.relforcerowsecurity,
       p.polpermissive,
       p.polcmd = '*',
       p.polroles = ARRAY[0::oid],
       pg_get_expr(p.polqual, p.polrelid),
       pg_get_expr(p.polwithcheck, p.polrelid)
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
  JOIN pg_policy AS p ON p.polrelid = c.oid
 WHERE n.nspname = $1
   AND c.relname = 'audit_events'
   AND p.polname = 'tenant_isolation'
`, schema).Scan(
		&rlsEnabled,
		&rlsForced,
		&permissive,
		&allCommands,
		&publicPolicy,
		&qual,
		&withCheck,
	); err != nil {
		t.Fatalf("inspect repaired audit policy in %s: %v", schema, err)
	}
	if !rlsEnabled || !rlsForced || !permissive || !allCommands || !publicPolicy {
		t.Fatalf(
			"repaired %s.audit_events catalog rls/force/permissive/all/public = %t/%t/%t/%t/%t",
			schema,
			rlsEnabled,
			rlsForced,
			permissive,
			allCommands,
			publicPolicy,
		)
	}
	if qual != withCheck ||
		!strings.Contains(qual, "tenant_id") ||
		!strings.Contains(qual, "probectl.tenant_id") ||
		strings.EqualFold(strings.TrimSpace(qual), "true") {
		t.Fatalf(
			"repaired %s.audit_events policy qual/check = %q / %q, want exact tenant-GUC equality",
			schema,
			qual,
			withCheck,
		)
	}

	if err := pool.QueryRow(context.Background(), `
SELECT has_schema_privilege('probectl_provider', $1, 'USAGE'),
       has_table_privilege('probectl_provider', $1 || '.audit_events', 'SELECT'),
       has_table_privilege('probectl_provider', $1 || '.audit_events', 'DELETE'),
       has_table_privilege('probectl_provider', $1 || '.audit_events', 'UPDATE'),
       has_table_privilege('probectl_app', $1 || '.audit_events', 'SELECT'),
       has_table_privilege('probectl_app', $1 || '.audit_events', 'INSERT'),
       has_table_privilege('probectl_app', $1 || '.audit_events', 'DELETE')
`, schema).Scan(
		&providerUsage,
		&providerSelect,
		&providerDelete,
		&providerUpdate,
		&appSelect,
		&appInsert,
		&appDelete,
	); err != nil {
		t.Fatalf("inspect repaired audit grants in %s: %v", schema, err)
	}
	if !providerUsage || !providerSelect || !providerDelete || providerUpdate ||
		!appSelect || !appInsert || appDelete {
		t.Fatalf(
			"repaired %s audit privileges provider(usage/select/delete/update)=%t/%t/%t/%t app(select/insert/delete)=%t/%t/%t",
			schema,
			providerUsage,
			providerSelect,
			providerDelete,
			providerUpdate,
			appSelect,
			appInsert,
			appDelete,
		)
	}
}

func qualifiedAuditCountAsApp(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	schema, tenantID string,
) int {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin qualified audit read: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		t.Fatalf("assume probectl_app for qualified audit read: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		tenantID,
	); err != nil {
		t.Fatalf("set tenant GUC for qualified audit read: %v", err)
	}

	var count int
	if err := tx.QueryRow(
		ctx,
		"SELECT count(*) FROM "+quoteIdent(schema)+`."audit_events"`,
	).Scan(&count); err != nil {
		t.Fatalf("qualified audit read in %s: %v", schema, err)
	}
	return count
}
