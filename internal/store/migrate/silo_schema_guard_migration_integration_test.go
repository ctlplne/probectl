// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package migrate_test

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/migrations"
)

func TestSiloSchemaGuardMigrationConvergesAsNonBypassOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	adminPool := isolatedMigrationPool(ctx, t)
	if _, err := migrate.New(migrationsThrough(t, 77), nil).Apply(ctx, adminPool); err != nil {
		t.Fatalf("apply through 0077: %v", err)
	}

	const (
		tenantA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		tenantB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		schemaA = "t_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
		schemaB = "t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
	)
	if _, err := adminPool.Exec(ctx, `
INSERT INTO tenants (id, slug, name, isolation_model) VALUES
  ($1::uuid, 'guard-migration-a', 'Guard Migration A', 'siloed'),
  ($2::uuid, 'guard-migration-b', 'Guard Migration B', 'siloed');
`, tenantA, tenantB); err != nil {
		t.Fatalf("seed guard migration tenants: %v", err)
	}
	for _, schema := range []string{schemaA, schemaB} {
		if _, err := adminPool.Exec(ctx,
			"CREATE SCHEMA "+quoteIdent(schema)); err != nil {
			t.Fatalf("create silo schema %s: %v", schema, err)
		}
		if _, err := adminPool.Exec(ctx,
			"CREATE TABLE "+quoteIdent(schema)+`.tests
			   (LIKE public.tests INCLUDING ALL)`); err != nil {
			t.Fatalf("create silo tests table %s: %v", schema, err)
		}
		table := quoteIdent(schema) + ".tests"
		for _, ddl := range []string{
			"GRANT USAGE ON SCHEMA " + quoteIdent(schema) + " TO probectl_app",
			"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY",
			"CREATE POLICY tenant_isolation ON " + table +
				" USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)" +
				" WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON " + table + " TO probectl_app",
		} {
			if _, err := adminPool.Exec(ctx, ddl); err != nil {
				t.Fatalf("prepare legacy table %s with %q: %v", schema, ddl, err)
			}
		}
	}
	if _, err := adminPool.Exec(ctx,
		"CREATE POLICY legacy_open ON "+quoteIdent(schemaB)+
			".tests AS PERMISSIVE FOR ALL USING (true) WITH CHECK (true)"); err != nil {
		t.Fatalf("create surviving permissive policy: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
INSERT INTO `+quoteIdent(schemaA)+`.tests
    (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
VALUES ($1::uuid, 'a-own', 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)
`, tenantA); err != nil {
		t.Fatalf("seed tenant A silo guard row: %v", err)
	}
	if _, err := adminPool.Exec(ctx, `
INSERT INTO `+quoteIdent(schemaB)+`.tests
    (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
VALUES
    ($1::uuid, 'b-own', 'icmp', '192.0.2.2', 60, 5, '{}'::jsonb, true),
    ($2::uuid, 'a-contamination', 'icmp', '192.0.2.3', 60, 5, '{}'::jsonb, true)
`, tenantB, tenantA); err != nil {
		t.Fatalf("seed tenant B silo guard rows: %v", err)
	}
	var physicalBefore int
	if err := adminPool.QueryRow(
		ctx,
		"SELECT count(*) FROM "+quoteIdent(schemaB)+".tests",
	).Scan(&physicalBefore); err != nil {
		t.Fatalf("count contaminated rows before migration: %v", err)
	}

	ownerPool := siloGuardMigrationOwnerPool(
		ctx,
		t,
		adminPool,
		[]string{schemaA, schemaB},
	)
	if _, err := migrate.New(migrationsThrough(t, 78), nil).Apply(ctx, ownerPool); err != nil {
		t.Fatalf("apply 0078 as non-bypass owner: %v", err)
	}
	body, err := fs.ReadFile(migrations.FS, "0078_silo_schema_tenant_guards.sql")
	if err != nil {
		t.Fatalf("read 0078 for replay: %v", err)
	}
	conn, err := ownerPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire migration owner for 0078 replay: %v", err)
	}
	if err := conn.Conn().PgConn().Exec(ctx, string(body)).Close(); err != nil {
		conn.Release()
		t.Fatalf("replay 0078 as non-bypass owner: %v", err)
	}
	conn.Release()

	for _, tc := range []struct {
		schema, tenant string
	}{
		{schema: schemaA, tenant: tenantA},
		{schema: schemaB, tenant: tenantB},
	} {
		assertMigrationSiloGuard(t, adminPool, tc.schema, "tests", tc.tenant)
	}
	var legacyStillPermissive bool
	if err := adminPool.QueryRow(ctx, `
SELECT permissive = 'PERMISSIVE'
  FROM pg_policies
 WHERE schemaname = $1
   AND tablename = 'tests'
   AND policyname = 'legacy_open'
`, schemaB).Scan(&legacyStillPermissive); err != nil || !legacyStillPermissive {
		t.Fatalf("0078 removed/changed legacy policy: permissive=%t err=%v", legacyStillPermissive, err)
	}
	var physicalAfter int
	if err := adminPool.QueryRow(
		ctx,
		"SELECT count(*) FROM "+quoteIdent(schemaB)+".tests",
	).Scan(&physicalAfter); err != nil {
		t.Fatalf("count contaminated rows after migration: %v", err)
	}
	if physicalAfter != physicalBefore {
		t.Fatalf("0078 changed physical rows = %d, want %d", physicalAfter, physicalBefore)
	}
	if got := qualifiedMigrationSiloCount(
		ctx,
		t,
		adminPool,
		schemaB,
		tenantA,
	); got != 0 {
		t.Fatalf("tenant A qualified visibility in migrated B silo = %d, want 0", got)
	}
	if got := qualifiedMigrationSiloCount(
		ctx,
		t,
		adminPool,
		schemaB,
		tenantB,
	); got != 1 {
		t.Fatalf("tenant B own visibility in migrated silo = %d, want 1", got)
	}
}

func TestSiloSchemaGuardMigrationRejectsInvalidTenantColumn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := isolatedMigrationPool(ctx, t)
	if _, err := migrate.New(migrationsThrough(t, 77), nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply through 0077: %v", err)
	}
	const (
		tenantID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		schema   = "t_eeeeeeeeeeee4eee8eeeeeeeeeeeeeee"
	)
	if _, err := pool.Exec(ctx, `
INSERT INTO tenants (id, slug, name, isolation_model)
VALUES ($1::uuid, 'invalid-silo-tenant-column', 'Invalid Silo Tenant Column', 'siloed')
`, tenantID); err != nil {
		t.Fatalf("seed invalid silo tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create invalid silo schema: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		"CREATE TABLE "+schema+".invalid_table (tenant_id text, value text)",
	); err != nil {
		t.Fatalf("seed invalid silo table: %v", err)
	}
	if _, err := migrate.New(migrationsThrough(t, 78), nil).Apply(ctx, pool); err == nil ||
		!containsAll(err.Error(), "tenant_id uuid NOT NULL", schema+".invalid_table") {
		t.Fatalf("0078 accepted invalid silo tenant column: %v", err)
	}
}

func siloGuardMigrationOwnerPool(
	ctx context.Context,
	t *testing.T,
	adminPool *pgxpool.Pool,
	schemas []string,
) *pgxpool.Pool {
	t.Helper()
	role := fmt.Sprintf("probectl_silo_guard_owner_%d", time.Now().UnixNano())
	quotedRole := quoteIdent(role)
	var adminUser string
	if err := adminPool.QueryRow(ctx, `SELECT current_user`).Scan(&adminUser); err != nil {
		t.Fatalf("read migration admin role: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		"CREATE ROLE "+quotedRole+" NOLOGIN NOSUPERUSER NOBYPASSRLS",
	); err != nil {
		t.Fatalf("create silo guard migration owner: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := adminPool.Exec(
			cleanupCtx,
			"REASSIGN OWNED BY "+quotedRole+" TO "+quoteIdent(adminUser),
		); err != nil {
			t.Errorf("reassign silo guard owner: %v", err)
			return
		}
		if _, err := adminPool.Exec(
			cleanupCtx,
			"DROP OWNED BY "+quotedRole,
		); err != nil {
			t.Errorf("drop silo guard owner grants: %v", err)
			return
		}
		if _, err := adminPool.Exec(cleanupCtx, "DROP ROLE "+quotedRole); err != nil {
			t.Errorf("drop silo guard owner: %v", err)
		}
	})

	for _, ddl := range []string{
		"GRANT USAGE, CREATE ON SCHEMA public TO " + quotedRole,
		"GRANT SELECT ON public.tenants TO " + quotedRole,
		"GRANT SELECT, INSERT ON public.schema_migrations TO " + quotedRole,
	} {
		if _, err := adminPool.Exec(ctx, ddl); err != nil {
			t.Fatalf("grant migration owner with %q: %v", ddl, err)
		}
	}
	for _, schema := range schemas {
		if _, err := adminPool.Exec(
			ctx,
			"GRANT USAGE, CREATE ON SCHEMA "+quoteIdent(schema)+" TO "+quotedRole,
		); err != nil {
			t.Fatalf("grant migration owner schema %s: %v", schema, err)
		}
		if _, err := adminPool.Exec(
			ctx,
			"ALTER TABLE "+quoteIdent(schema)+".tests OWNER TO "+quotedRole,
		); err != nil {
			t.Fatalf("transfer silo table %s to migration owner: %v", schema, err)
		}
	}

	cfg := adminPool.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+quotedRole)
		return err
	}
	ownerPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open silo guard migration owner pool: %v", err)
	}
	t.Cleanup(ownerPool.Close)
	if err := ownerPool.Ping(ctx); err != nil {
		t.Fatalf("ping silo guard migration owner pool: %v", err)
	}
	var current string
	var super, bypass bool
	if err := ownerPool.QueryRow(ctx, `
SELECT current_user, rolsuper, rolbypassrls
  FROM pg_roles
 WHERE rolname = current_user
`).Scan(&current, &super, &bypass); err != nil {
		t.Fatalf("inspect silo guard migration owner: %v", err)
	}
	if current != role || super || bypass {
		t.Fatalf(
			"silo guard migration owner=%q super=%t bypass=%t, want %q/false/false",
			current,
			super,
			bypass,
			role,
		)
	}
	return ownerPool
}

func assertMigrationSiloGuard(
	t *testing.T,
	pool *pgxpool.Pool,
	schema, table, tenantID string,
) {
	t.Helper()
	var (
		enabled, forced, restrictive, allPublic bool
		usingExpr, checkExpr                    string
	)
	if err := pool.QueryRow(context.Background(), `
SELECT c.relrowsecurity,
       c.relforcerowsecurity,
       NOT p.polpermissive,
       p.polcmd = '*' AND p.polroles = ARRAY[0::oid],
       pg_get_expr(p.polqual, p.polrelid),
       pg_get_expr(p.polwithcheck, p.polrelid)
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
  JOIN pg_policy AS p
    ON p.polrelid = c.oid
   AND p.polname = 'tenant_schema_isolation'
 WHERE n.nspname = $1
   AND c.relname = $2
`, schema, table).Scan(
		&enabled,
		&forced,
		&restrictive,
		&allPublic,
		&usingExpr,
		&checkExpr,
	); err != nil {
		t.Fatalf("inspect migrated guard %s.%s: %v", schema, table, err)
	}
	expected := normalizeMigrationPolicy(
		`tenant_id = '` + tenantID + `'::uuid AND ` +
			`tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid`,
	)
	if !enabled || !forced || !restrictive || !allPublic ||
		normalizeMigrationPolicy(usingExpr) != expected ||
		normalizeMigrationPolicy(checkExpr) != expected {
		t.Fatalf(
			"migrated %s.%s guard enabled/forced/restrictive/all_public=%t/%t/%t/%t qual=%q check=%q",
			schema,
			table,
			enabled,
			forced,
			restrictive,
			allPublic,
			usingExpr,
			checkExpr,
		)
	}
}

func qualifiedMigrationSiloCount(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	schema, tenantID string,
) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin migrated silo read: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		t.Fatalf("assume app role for migrated silo read: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		tenantID,
	); err != nil {
		t.Fatalf("set migrated silo tenant GUC: %v", err)
	}
	var count int
	if err := tx.QueryRow(
		ctx,
		"SELECT count(*) FROM "+quoteIdent(schema)+".tests",
	).Scan(&count); err != nil {
		t.Fatalf("read migrated silo %s: %v", schema, err)
	}
	return count
}

func normalizeMigrationPolicy(expression string) string {
	var out []byte
	inLiteral := false
	for i := 0; i < len(expression); i++ {
		ch := expression[i]
		if ch == '\'' {
			out = append(out, ch)
			if inLiteral && i+1 < len(expression) && expression[i+1] == '\'' {
				out = append(out, expression[i+1])
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
		out = append(out, ch)
	}
	return string(out)
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
