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

// TestSiloSchemaWriteIsolationWithLegacyPermissivePolicy proves the physical
// schema is itself a tenant boundary. The restored fixture starts in the two
// independently reproduced fail-before states: a caller scoped to tenant A can
// insert an A row into tenant B's table, and a surviving permissive policy
// exposes B rows to A. CatchUp must add a schema-bound RESTRICTIVE guard without
// deleting the contaminated row or relying on handler predicates.
func TestSiloSchemaWriteIsolationWithLegacyPermissivePolicy(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)

	tenantA := mkTenant(t, pool, "schema-write-a-"+stamp, "siloed", "")
	tenantB := mkTenant(t, pool, "schema-write-b-"+stamp, "siloed", "")
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

	schemaA := SchemaName(tenantA)
	schemaB := SchemaName(tenantB)
	if err := adminInsertSiloTest(ctx, pool, schemaA, tenantA, "a-original"); err != nil {
		t.Fatalf("seed tenant A own row: %v", err)
	}
	if err := adminInsertSiloTest(ctx, pool, schemaB, tenantB, "b-original"); err != nil {
		t.Fatalf("seed tenant B own row: %v", err)
	}

	tableB := quoteIdent(schemaB) + `."tests"`
	for _, stmt := range []string{
		"DROP POLICY IF EXISTS tenant_schema_isolation ON " + tableB,
		"DROP POLICY IF EXISTS tenant_isolation ON " + tableB,
		`CREATE POLICY tenant_isolation ON ` + tableB + `
		   USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
		   WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)`,
		"DROP POLICY IF EXISTS legacy_open ON " + tableB,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare legacy silo policy with %q: %v", stmt, err)
		}
	}

	// Fail-before proof 1: a GUC-only policy accepts tenant A's row into tenant
	// B's physical table.
	if _, err := appInsertSiloTest(
		ctx,
		pool,
		schemaB,
		tenantA,
		tenantA,
		"a-injected-into-b",
	); err != nil {
		t.Fatalf("legacy GUC-only cross-schema insert precondition: %v", err)
	}
	if got := appCountSiloTests(ctx, t, pool, schemaB, tenantA); got != 1 {
		t.Fatalf("GUC-only cross-schema contamination visibility = %d, want 1", got)
	}

	// Fail-before proof 2: permissive policies OR together, so legacy_open lets
	// tenant A read tenant B's own row as well as the injected contamination.
	if _, err := pool.Exec(
		ctx,
		"CREATE POLICY legacy_open ON "+tableB+
			" AS PERMISSIVE FOR ALL USING (true) WITH CHECK (true)",
	); err != nil {
		t.Fatalf("create legacy permissive bypass policy: %v", err)
	}
	if got := appCountSiloTests(ctx, t, pool, schemaB, tenantA); got != 2 {
		t.Fatalf("legacy permissive cross-schema read precondition = %d, want 2", got)
	}
	physicalBefore := adminCountSiloTests(ctx, t, pool, schemaB)

	for _, tenantID := range tenants {
		if err := provisioner.CatchUp(ctx, tenantID); err != nil {
			t.Fatalf("catch up silo %s: %v", tenantID, err)
		}
		if err := provisioner.CatchUp(ctx, tenantID); err != nil {
			t.Fatalf("repeat catch up silo %s: %v", tenantID, err)
		}
		assertEverySiloTableHasSchemaGuard(t, pool, SchemaName(tenantID), tenantID)
	}

	// Catch-up is non-destructive: contamination remains physically present,
	// but no tenant role can access or mutate it.
	if physicalAfter := adminCountSiloTests(ctx, t, pool, schemaB); physicalAfter != physicalBefore {
		t.Fatalf(
			"catch-up changed contaminated physical row count = %d, want %d",
			physicalAfter,
			physicalBefore,
		)
	}
	var legacyPermissive bool
	if err := pool.QueryRow(ctx, `
SELECT permissive = 'PERMISSIVE'
  FROM pg_policies
 WHERE schemaname = $1
   AND tablename = 'tests'
   AND policyname = 'legacy_open'
`, schemaB).Scan(&legacyPermissive); err != nil || !legacyPermissive {
		t.Fatalf("legacy permissive policy must survive catch-up: permissive=%t err=%v", legacyPermissive, err)
	}

	if got := appCountSiloTests(ctx, t, pool, schemaB, tenantA); got != 0 {
		t.Fatalf("tenant A qualified read in tenant B silo = %d, want 0", got)
	}
	if got := appCountSiloTests(ctx, t, pool, schemaA, tenantB); got != 0 {
		t.Fatalf("tenant B qualified read in tenant A silo = %d, want 0", got)
	}
	if _, err := appInsertSiloTest(
		ctx,
		pool,
		schemaB,
		tenantA,
		tenantA,
		"a-reinjected-into-b",
	); err == nil {
		t.Fatal("tenant A inserted an A row into tenant B silo after repair")
	}
	if _, err := appInsertSiloTest(
		ctx,
		pool,
		schemaB,
		tenantA,
		tenantB,
		"b-row-with-a-guc",
	); err == nil {
		t.Fatal("tenant A GUC inserted a B row into tenant B silo after repair")
	}
	if affected, err := appMutateSiloTests(
		ctx,
		pool,
		schemaB,
		tenantA,
		`UPDATE `+tableB+` SET name = 'cross-updated'`,
	); err != nil || affected != 0 {
		t.Fatalf("tenant A cross-schema update = (%d, %v), want (0, nil)", affected, err)
	}
	if affected, err := appMutateSiloTests(
		ctx,
		pool,
		schemaB,
		tenantA,
		`DELETE FROM `+tableB,
	); err != nil || affected != 0 {
		t.Fatalf("tenant A cross-schema delete = (%d, %v), want (0, nil)", affected, err)
	}

	// Own-tenant CRUD remains functional under the stricter boundary.
	ownID, err := appInsertSiloTest(
		ctx,
		pool,
		schemaA,
		tenantA,
		tenantA,
		"a-own-crud",
	)
	if err != nil {
		t.Fatalf("tenant A own insert: %v", err)
	}
	ownTable := quoteIdent(schemaA) + `."tests"`
	if affected, err := appMutateSiloTests(
		ctx,
		pool,
		schemaA,
		tenantA,
		`UPDATE `+ownTable+` SET name = 'a-own-updated' WHERE id = $1::uuid`,
		ownID,
	); err != nil || affected != 1 {
		t.Fatalf("tenant A own update = (%d, %v), want (1, nil)", affected, err)
	}
	if affected, err := appMutateSiloTests(
		ctx,
		pool,
		schemaA,
		tenantA,
		`DELETE FROM `+ownTable+` WHERE id = $1::uuid`,
		ownID,
	); err != nil || affected != 1 {
		t.Fatalf("tenant A own delete = (%d, %v), want (1, nil)", affected, err)
	}
	if got := appCountSiloTests(ctx, t, pool, schemaB, tenantB); got != 1 {
		t.Fatalf("tenant B own visible rows = %d, want 1 (contamination hidden)", got)
	}
}

func adminInsertSiloTest(
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, tenantID, name string,
) error {
	_, err := pool.Exec(
		ctx,
		`INSERT INTO `+quoteIdent(schema)+`."tests"
		    (tenant_id, name, type, target, interval_seconds,
		     timeout_seconds, params, enabled)
		 VALUES ($1::uuid, $2, 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`,
		tenantID,
		name,
	)
	return err
}

func appInsertSiloTest(
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, callerTenant, rowTenant, name string,
) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		callerTenant,
	); err != nil {
		return "", err
	}
	var id string
	if err := tx.QueryRow(
		ctx,
		`INSERT INTO `+quoteIdent(schema)+`."tests"
		    (tenant_id, name, type, target, interval_seconds,
		     timeout_seconds, params, enabled)
		 VALUES ($1::uuid, $2, 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)
		 RETURNING id::text`,
		rowTenant,
		name,
	).Scan(&id); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

func appMutateSiloTests(
	ctx context.Context,
	pool *pgxpool.Pool,
	_ string,
	callerTenant, statement string,
	args ...any,
) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		callerTenant,
	); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, statement, args...)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func appCountSiloTests(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	schema, callerTenant string,
) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin qualified silo count: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		t.Fatalf("assume app role for qualified silo count: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		callerTenant,
	); err != nil {
		t.Fatalf("set tenant GUC for qualified silo count: %v", err)
	}
	var count int
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM `+quoteIdent(schema)+`."tests"`,
	).Scan(&count); err != nil {
		t.Fatalf("qualified silo count: %v", err)
	}
	return count
}

func adminCountSiloTests(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	schema string,
) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM `+quoteIdent(schema)+`."tests"`,
	).Scan(&count); err != nil {
		t.Fatalf("admin physical silo count: %v", err)
	}
	return count
}

func assertEverySiloTableHasSchemaGuard(
	t *testing.T,
	pool *pgxpool.Pool,
	schema, tenantID string,
) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
SELECT c.relname,
       c.relrowsecurity,
       c.relforcerowsecurity,
       p.oid IS NOT NULL,
       COALESCE(NOT p.polpermissive, false),
       COALESCE(p.polcmd = '*', false),
       COALESCE(p.polroles = ARRAY[0::oid], false),
       COALESCE(pg_get_expr(p.polqual, p.polrelid), ''),
       COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '')
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
  JOIN pg_attribute AS a
    ON a.attrelid = c.oid
   AND a.attname = 'tenant_id'
   AND NOT a.attisdropped
  LEFT JOIN pg_policy AS p
    ON p.polrelid = c.oid
   AND p.polname = 'tenant_schema_isolation'
 WHERE c.relkind = 'r'
   AND n.nspname = $1
 ORDER BY c.relname
`, schema)
	if err != nil {
		t.Fatalf("enumerate schema guards in %s: %v", schema, err)
	}
	defer rows.Close()

	checked := 0
	expected := normalizeSiloPolicyExpression(
		`tenant_id = '` + tenantID + `'::uuid AND ` +
			`tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid`,
	)
	for rows.Next() {
		var (
			table                            string
			enabled, forced, present         bool
			restrictive, all, public         bool
			usingExpression, checkExpression string
		)
		if err := rows.Scan(
			&table,
			&enabled,
			&forced,
			&present,
			&restrictive,
			&all,
			&public,
			&usingExpression,
			&checkExpression,
		); err != nil {
			t.Fatalf("scan schema guard in %s: %v", schema, err)
		}
		checked++
		if !enabled || !forced || !present || !restrictive || !all || !public ||
			normalizeSiloPolicyExpression(usingExpression) != expected ||
			normalizeSiloPolicyExpression(checkExpression) != expected {
			t.Fatalf(
				"%s.%s schema guard enabled/forced/present/restrictive/all/public=%t/%t/%t/%t/%t/%t qual=%q check=%q",
				schema,
				table,
				enabled,
				forced,
				present,
				restrictive,
				all,
				public,
				usingExpression,
				checkExpression,
			)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema guards in %s: %v", schema, err)
	}
	if checked == 0 {
		t.Fatalf("no tenant tables checked in %s", schema)
	}
}

func normalizeSiloPolicyExpression(expression string) string {
	var normalized strings.Builder
	inLiteral := false
	for i := 0; i < len(expression); i++ {
		ch := expression[i]
		if ch == '\'' {
			normalized.WriteByte(ch)
			if inLiteral && i+1 < len(expression) && expression[i+1] == '\'' {
				normalized.WriteByte(expression[i+1])
				i++
				continue
			}
			inLiteral = !inLiteral
			continue
		}
		if !inLiteral {
			switch ch {
			case ' ', '\t', '\r', '\n', '(', ')':
				continue
			}
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
		}
		normalized.WriteByte(ch)
	}
	return normalized.String()
}
