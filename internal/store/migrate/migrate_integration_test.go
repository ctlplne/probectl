// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package migrate_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
}

func TestApplyNoTxConcurrentIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}

	suffix := time.Now().UnixNano()
	table := fmt.Sprintf("migrate_no_tx_%d", suffix)
	index := fmt.Sprintf("%s_value_idx", table)
	version := suffix
	defer func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table)
	}()

	fsys := fstest.MapFS{
		fmt.Sprintf("%d_create.sql", version): {Data: []byte(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id bigint PRIMARY KEY, value text);", table))},
		fmt.Sprintf("%d_index.sql", version+1): {Data: []byte(fmt.Sprintf(`-- probectl:no-tx: CREATE INDEX CONCURRENTLY cannot run in PostgreSQL's migration transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS %s ON %s (value);`, index, table))},
	}

	applied, err := migrate.New(fsys, nil).Apply(ctx, pool)
	if err != nil {
		t.Fatalf("apply no-tx concurrent index migration: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied versions = %v, want two migrations", applied)
	}
	var got string
	if err := pool.QueryRow(ctx, `SELECT indexname FROM pg_indexes WHERE tablename = $1 AND indexname = $2`, table, index).Scan(&got); err != nil {
		t.Fatalf("created concurrent index not found: %v", err)
	}
	if got != index {
		t.Fatalf("index = %q, want %q", got, index)
	}
}

// TestApplyIsIdempotent proves the S1 Done-when: a no-op (already-applied)
// migration run on a second boot applies nothing.
func TestApplyIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}

	runner := migrate.New(migrations.FS, nil)

	// Apply serializes on a Postgres advisory lock, so this is safe to run
	// concurrently with other packages migrating the same shared database. We do
	// NOT drop the schema (that would race other appliers); instead we assert the
	// invariant that matters: after a first apply, a second apply changes nothing.
	if _, err := runner.Apply(ctx, pool); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	applied, err := runner.Apply(ctx, pool)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second apply must be a no-op, but applied %v", applied)
	}

	var value string
	if err := pool.QueryRow(ctx, "SELECT value FROM probectl_meta WHERE key = 'schema_baseline'").Scan(&value); err != nil {
		t.Fatalf("baseline marker row: %v", err)
	}
	if value != "s1" {
		t.Errorf("schema_baseline = %q, want s1", value)
	}
}

func TestMigrationContentPreservesTenantData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := isolatedMigrationPool(ctx, t)

	runner := migrate.New(migrationsThrough(t, 9), nil)
	if _, err := runner.Apply(ctx, pool); err != nil {
		t.Fatalf("apply through 0009: %v", err)
	}
	seedPreTestsDefinitionData(ctx, t, pool)

	runner = migrate.New(migrationsThrough(t, 47), nil)
	if _, err := runner.Apply(ctx, pool); err != nil {
		t.Fatalf("apply through 0047: %v", err)
	}
	seedPreStrictOTLPTokenData(ctx, t, pool)

	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply latest migrations: %v", err)
	}

	assertTestsDefinitionDataPreserved(ctx, t, pool)
	assertOTLPTokenDataPreserved(ctx, t, pool)
}

func TestAuditStreamHeadMigrationBackfillsRetainedBoundaryAsNonBypassOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := isolatedMigrationPool(ctx, t)
	if _, err := migrate.New(migrationsThrough(t, 74), nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply through 0074: %v", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO tenants (id, slug, name, isolation_model) VALUES
  ($1, 'audit-head-migration-a', 'Audit Head Migration A', 'pooled'),
  ($2, 'audit-head-migration-b', 'Audit Head Migration B', 'siloed');
`, migrationTenantA, migrationTenantB); err != nil {
		t.Fatalf("seed pre-0075 tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `
CREATE SCHEMA t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb;
GRANT USAGE ON SCHEMA t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb TO probectl_app;
CREATE TABLE t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events
  (LIKE public.audit_events INCLUDING ALL);
ALTER TABLE t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events
  FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation
  ON t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
-- This is the pre-0075 provisioner shape being repaired: app DELETE was
-- accidentally broad and provider retention had no silo capability.
GRANT SELECT, INSERT, UPDATE, DELETE
  ON t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events TO probectl_app;
`); err != nil {
		t.Fatalf("seed pre-0075 silo audit grants: %v", err)
	}
	if _, err := pool.Exec(ctx, `
-- Tenant A and the provider stream model a previously partial prune: seq 1-2
-- are gone, and seq 3's prev_hash is the exact surviving boundary anchor.
INSERT INTO audit_events
  (tenant_id, seq, actor, action, target, data, prev_hash, hash)
VALUES
  ($1, 3, 'migration', 'seed', 'a-3', '{}'::jsonb, 'tenant-a-hash-2', 'tenant-a-hash-3'),
  ($1, 4, 'migration', 'seed', 'a-4', '{}'::jsonb, 'tenant-a-hash-3', 'tenant-a-hash-4');
`, migrationTenantA); err != nil {
		t.Fatalf("seed pre-0075 tenant audit streams: %v", err)
	}
	if _, err := pool.Exec(ctx, `
-- A stale/misrouted public row for the silo tenant must never win over the
-- tenant's active physical stream during head backfill.
INSERT INTO public.audit_events
  (tenant_id, seq, actor, action, target, data, prev_hash, hash)
VALUES
  ($1, 99, 'migration', 'stale', 'b-public-stale', '{}'::jsonb,
   'stale-public-prev', 'stale-public-hash');
`, migrationTenantB); err != nil {
		t.Fatalf("seed stale public silo audit row: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events
  (tenant_id, seq, actor, action, target, data, prev_hash, hash)
VALUES
  ($1, 1, 'migration', 'seed', 'b-1', '{}'::jsonb, '', 'tenant-b-hash-1');
`, migrationTenantB); err != nil {
		t.Fatalf("seed pre-0075 silo audit stream: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO provider_audit_events
  (seq, actor, action, target, data, prev_hash, hash)
VALUES
  (3, 'migration', 'seed', 'p-3', '{}'::jsonb, 'provider-hash-2', 'provider-hash-3'),
  (4, 'migration', 'seed', 'p-4', '{}'::jsonb, 'provider-hash-3', 'provider-hash-4');
`); err != nil {
		t.Fatalf("seed pre-0075 provider audit stream: %v", err)
	}

	ownerPool := auditHeadMigrationOwnerPool(ctx, t, pool)
	if _, err := migrate.New(migrationsThrough(t, 75), nil).Apply(ctx, ownerPool); err != nil {
		t.Fatalf("apply 0075: %v", err)
	}
	migrationBody, err := fs.ReadFile(
		migrations.FS,
		"0075_audit_stream_heads.sql",
	)
	if err != nil {
		t.Fatalf("read 0075 for idempotent replay: %v", err)
	}
	ownerConn, err := ownerPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire non-bypass migration owner for replay: %v", err)
	}
	if err := ownerConn.Conn().PgConn().Exec(ctx, string(migrationBody)).Close(); err != nil {
		ownerConn.Release()
		t.Fatalf("replay 0075 under forced RLS as non-bypass owner: %v", err)
	}
	ownerConn.Release()

	for _, tc := range []struct {
		tenant               string
		headSeq, prunedSeq   int64
		headHash, prunedHash string
	}{
		{
			tenant: migrationTenantA, headSeq: 4, headHash: "tenant-a-hash-4",
			prunedSeq: 2, prunedHash: "tenant-a-hash-2",
		},
		{
			tenant: migrationTenantB, headSeq: 1, headHash: "tenant-b-hash-1",
			prunedSeq: 0, prunedHash: "",
		},
	} {
		var headSeq, prunedSeq int64
		var headHash, prunedHash string
		if err := pool.QueryRow(
			ctx,
			`SELECT head_seq, head_hash, pruned_seq, pruned_hash
			   FROM audit_stream_heads
			  WHERE tenant_id = $1::uuid`,
			tc.tenant,
		).Scan(&headSeq, &headHash, &prunedSeq, &prunedHash); err != nil {
			t.Fatalf("read tenant %s audit head: %v", tc.tenant, err)
		}
		if headSeq != tc.headSeq || headHash != tc.headHash ||
			prunedSeq != tc.prunedSeq || prunedHash != tc.prunedHash {
			t.Fatalf(
				"tenant %s head = (%d,%q,%d,%q), want (%d,%q,%d,%q)",
				tc.tenant,
				headSeq,
				headHash,
				prunedSeq,
				prunedHash,
				tc.headSeq,
				tc.headHash,
				tc.prunedSeq,
				tc.prunedHash,
			)
		}
	}

	var (
		headRLSEnabled bool
		headRLSForced  bool
		tempPolicies   int
	)
	if err := pool.QueryRow(ctx, `
SELECT c.relrowsecurity,
       c.relforcerowsecurity,
       (
           SELECT count(*)
             FROM pg_policy
            WHERE polrelid = 'public.audit_stream_heads'::regclass
              AND polname IN (
                  'audit_stream_head_migration_read',
                  'audit_stream_head_migration_backfill'
              )
       )
  FROM pg_class AS c
 WHERE c.oid = 'public.audit_stream_heads'::regclass
`).Scan(&headRLSEnabled, &headRLSForced, &tempPolicies); err != nil {
		t.Fatalf("inspect replayed audit head RLS: %v", err)
	}
	if !headRLSEnabled || !headRLSForced || tempPolicies != 0 {
		t.Fatalf(
			"replayed audit head RLS enabled/forced/temp-policies = %t/%t/%d, want true/true/0",
			headRLSEnabled,
			headRLSForced,
			tempPolicies,
		)
	}

	var providerHead, providerPruned int64
	var providerHeadHash, providerPrunedHash string
	if err := pool.QueryRow(
		ctx,
		`SELECT head_seq, head_hash, pruned_seq, pruned_hash
		   FROM provider_audit_stream_head
		  WHERE singleton`,
	).Scan(
		&providerHead,
		&providerHeadHash,
		&providerPruned,
		&providerPrunedHash,
	); err != nil {
		t.Fatalf("read provider audit head: %v", err)
	}
	if providerHead != 4 || providerHeadHash != "provider-hash-4" ||
		providerPruned != 2 || providerPrunedHash != "provider-hash-2" {
		t.Fatalf(
			"provider head = (%d,%q,%d,%q), want (4,%q,2,%q)",
			providerHead,
			providerHeadHash,
			providerPruned,
			providerPrunedHash,
			"provider-hash-4",
			"provider-hash-2",
		)
	}

	var (
		providerSchemaUsage bool
		providerSelect      bool
		providerDelete      bool
		providerUpdate      bool
		appInsert           bool
		appDelete           bool
	)
	if err := pool.QueryRow(ctx, `
SELECT has_schema_privilege(
           'probectl_provider',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb',
           'USAGE'
       ),
       has_table_privilege(
           'probectl_provider',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events',
           'SELECT'
       ),
       has_table_privilege(
           'probectl_provider',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events',
           'DELETE'
       ),
       has_table_privilege(
           'probectl_provider',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events',
           'UPDATE'
       ),
       has_table_privilege(
           'probectl_app',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events',
           'INSERT'
       ),
       has_table_privilege(
           'probectl_app',
           't_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb.audit_events',
           'DELETE'
       )
`).Scan(
		&providerSchemaUsage,
		&providerSelect,
		&providerDelete,
		&providerUpdate,
		&appInsert,
		&appDelete,
	); err != nil {
		t.Fatalf("read repaired silo audit privileges: %v", err)
	}
	if !providerSchemaUsage || !providerSelect || !providerDelete ||
		providerUpdate || !appInsert || appDelete {
		t.Fatalf(
			"repaired silo privileges provider(usage/select/delete/update)=%t/%t/%t/%t app(insert/delete)=%t/%t",
			providerSchemaUsage,
			providerSelect,
			providerDelete,
			providerUpdate,
			appInsert,
			appDelete,
		)
	}
}

// auditHeadMigrationOwnerPool transfers only the objects touched by 0075 to a
// fresh table owner with the production-safe NOSUPERUSER/NOBYPASSRLS posture.
// Connections still authenticate with the disposable database's admin login,
// then assume that owner before the migration runner performs any work.
func auditHeadMigrationOwnerPool(
	ctx context.Context,
	t *testing.T,
	adminPool *pgxpool.Pool,
) *pgxpool.Pool {
	t.Helper()

	role := fmt.Sprintf("probectl_migration_owner_%d", time.Now().UnixNano())
	quotedRole := quoteIdent(role)
	var adminUser string
	if err := adminPool.QueryRow(ctx, `SELECT current_user`).Scan(&adminUser); err != nil {
		t.Fatalf("read migration test admin role: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		"CREATE ROLE "+quotedRole+" NOLOGIN NOSUPERUSER NOBYPASSRLS",
	); err != nil {
		t.Fatalf("create non-bypass migration owner: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := adminPool.Exec(
			cleanupCtx,
			"REASSIGN OWNED BY "+quotedRole+" TO "+quoteIdent(adminUser),
		); err != nil {
			t.Errorf("reassign migration test owner: %v", err)
			return
		}
		if _, err := adminPool.Exec(
			cleanupCtx,
			"DROP OWNED BY "+quotedRole,
		); err != nil {
			t.Errorf("drop migration test owner grants: %v", err)
			return
		}
		if _, err := adminPool.Exec(cleanupCtx, "DROP ROLE "+quotedRole); err != nil {
			t.Errorf("drop migration test owner: %v", err)
		}
	})

	const siloSchema = "t_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
	for _, stmt := range []string{
		"GRANT USAGE, CREATE ON SCHEMA public TO " + quotedRole,
		"GRANT USAGE, CREATE ON SCHEMA " + siloSchema + " TO " + quotedRole + " WITH GRANT OPTION",
		"ALTER TABLE public.schema_migrations OWNER TO " + quotedRole,
		"ALTER TABLE public.tenants OWNER TO " + quotedRole,
		"ALTER TABLE public.audit_events OWNER TO " + quotedRole,
		"ALTER TABLE public.provider_audit_events OWNER TO " + quotedRole,
		"ALTER TABLE " + siloSchema + ".audit_events OWNER TO " + quotedRole,
	} {
		if _, err := adminPool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare non-bypass migration owner with %q: %v", stmt, err)
		}
	}

	cfg := adminPool.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+quotedRole)
		return err
	}
	ownerPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open non-bypass migration owner pool: %v", err)
	}
	t.Cleanup(ownerPool.Close)
	if err := ownerPool.Ping(ctx); err != nil {
		t.Fatalf("ping non-bypass migration owner pool: %v", err)
	}

	var (
		currentUser string
		superuser   bool
		bypassRLS   bool
	)
	if err := ownerPool.QueryRow(
		ctx,
		`SELECT current_user, rolsuper, rolbypassrls
		   FROM pg_roles
		  WHERE rolname = current_user`,
	).Scan(&currentUser, &superuser, &bypassRLS); err != nil {
		t.Fatalf("inspect non-bypass migration owner: %v", err)
	}
	if currentUser != role || superuser || bypassRLS {
		t.Fatalf(
			"migration owner = %q superuser=%t bypassrls=%t, want %q/false/false",
			currentUser,
			superuser,
			bypassRLS,
			role,
		)
	}
	return ownerPool
}

const (
	migrationTenantA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	migrationTenantB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	migrationTestA1 = "10000000-0000-4000-8000-000000000001"
	migrationTestA2 = "10000000-0000-4000-8000-000000000002"
	migrationTestB1 = "10000000-0000-4000-8000-000000000003"

	migrationOTLPTokenA = "20000000-0000-4000-8000-000000000001"
	migrationOTLPTokenB = "20000000-0000-4000-8000-000000000002"
)

var (
	migrationOTLPHashA = []byte("old-token-hash-a")
	migrationOTLPHashB = []byte("old-token-hash-b")
)

func isolatedMigrationPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	baseCfg, err := pgxpool.ParseConfig(dsn())
	if err != nil {
		t.Fatalf("parse PROBECTL_DATABASE_URL: %v", err)
	}
	adminCfg := baseCfg.Copy()
	adminCfg.ConnConfig.Database = "postgres"
	adminPool, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	if err := adminPool.Ping(ctx); err != nil {
		adminPool.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	t.Cleanup(adminPool.Close)

	dbName := fmt.Sprintf("probectl_migrate_content_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+quoteIdent(dbName)); err != nil {
		t.Fatalf("create isolated migration database %q: %v", dbName, err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdent(dbName)+" WITH (FORCE)")
	})

	dbCfg := baseCfg.Copy()
	dbCfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, dbCfg)
	if err != nil {
		t.Fatalf("connect isolated migration database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping isolated migration database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func migrationsThrough(t *testing.T, maxVersion int64) fstest.MapFS {
	t.Helper()

	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	out := fstest.MapFS{}
	for _, name := range names {
		base := strings.TrimSuffix(name, ".sql")
		i := strings.IndexByte(base, '_')
		if i <= 0 {
			t.Fatalf("migration %q must be named NNNN_description.sql", name)
		}
		version, err := strconv.ParseInt(base[:i], 10, 64)
		if err != nil {
			t.Fatalf("parse migration version %q: %v", name, err)
		}
		if version > maxVersion {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read embedded migration %q: %v", name, err)
		}
		out[name] = &fstest.MapFile{Data: body}
	}
	if len(out) == 0 {
		t.Fatalf("no migrations found through version %d", maxVersion)
	}
	return out
}

func seedPreTestsDefinitionData(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(ctx, `
INSERT INTO tenants (id, slug, name) VALUES
  ($1, 'migration-tenant-a', 'Migration Tenant A'),
  ($2, 'migration-tenant-b', 'Migration Tenant B')
ON CONFLICT (id) DO NOTHING;
`, migrationTenantA, migrationTenantB)
	if err != nil {
		t.Fatalf("seed migration tenants: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO tests (id, tenant_id, name, created_at) VALUES
  ($1, $2, 'shared-latency', '2024-01-02T03:04:05Z'),
  ($3, $2, 'tenant-a-http', '2024-01-02T03:05:05Z'),
  ($4, $5, 'shared-latency', '2024-01-02T03:06:05Z');
`, migrationTestA1, migrationTenantA, migrationTestA2, migrationTestB1, migrationTenantB)
	if err != nil {
		t.Fatalf("seed pre-0010 tests data: %v", err)
	}
}

func seedPreStrictOTLPTokenData(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(ctx, `
INSERT INTO otlp_tokens (id, tenant_id, name, token_hash, created_at) VALUES
  ($1, $2, 'tenant-a-token', $3, '2024-01-03T00:00:00Z'),
  ($4, $5, 'tenant-b-token', $6, '2024-01-03T00:01:00Z');
`, migrationOTLPTokenA, migrationTenantA, migrationOTLPHashA, migrationOTLPTokenB, migrationTenantB, migrationOTLPHashB)
	if err != nil {
		t.Fatalf("seed pre-0048 otlp token data: %v", err)
	}
}

func assertTestsDefinitionDataPreserved(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	var total int
	if err := pool.QueryRow(ctx, `
SELECT count(*)
  FROM tests
 WHERE id IN ($1::uuid, $2::uuid, $3::uuid)
`, migrationTestA1, migrationTestA2, migrationTestB1).Scan(&total); err != nil {
		t.Fatalf("count migrated test rows: %v", err)
	}
	if total != 3 {
		t.Fatalf("migrated test rows = %d, want 3", total)
	}
	assertMigratedTestRow(ctx, t, pool, migrationTestA1, migrationTenantA, "shared-latency")
	assertMigratedTestRow(ctx, t, pool, migrationTestA2, migrationTenantA, "tenant-a-http")
	assertMigratedTestRow(ctx, t, pool, migrationTestB1, migrationTenantB, "shared-latency")

	if got := tenantVisibleCount(ctx, t, pool, migrationTenantA, "tests", "id IN ($1::uuid, $2::uuid, $3::uuid)", migrationTestA1, migrationTestA2, migrationTestB1); got != 2 {
		t.Fatalf("tenant A visible tests = %d, want 2", got)
	}
	if got := tenantVisibleCount(ctx, t, pool, migrationTenantB, "tests", "id IN ($1::uuid, $2::uuid, $3::uuid)", migrationTestA1, migrationTestA2, migrationTestB1); got != 1 {
		t.Fatalf("tenant B visible tests = %d, want 1", got)
	}
	if got := tenantVisibleCount(ctx, t, pool, "", "tests", "id IN ($1::uuid, $2::uuid, $3::uuid)", migrationTestA1, migrationTestA2, migrationTestB1); got != 0 {
		t.Fatalf("unset-tenant visible tests = %d, want fail-closed 0", got)
	}
}

func assertMigratedTestRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id, tenantID, name string) {
	t.Helper()

	var gotTenant, gotName, testType, target, params string
	var interval, timeout int
	var enabled, hasUpdatedAt bool
	err := pool.QueryRow(ctx, `
SELECT tenant_id::text, name, type, target, interval_seconds, timeout_seconds,
       params::text, enabled, updated_at IS NOT NULL
  FROM tests
 WHERE id = $1::uuid
`, id).Scan(&gotTenant, &gotName, &testType, &target, &interval, &timeout, &params, &enabled, &hasUpdatedAt)
	if err != nil {
		t.Fatalf("query migrated test row %s: %v", id, err)
	}
	if gotTenant != tenantID || gotName != name {
		t.Fatalf("migrated test identity = tenant %q name %q, want tenant %q name %q", gotTenant, gotName, tenantID, name)
	}
	if testType != "" || target != "" || interval != 60 || timeout != 3 || params != "{}" || !enabled || !hasUpdatedAt {
		t.Fatalf("migrated test defaults = type %q target %q interval %d timeout %d params %s enabled %v updated_at %v, want 0010 defaults", testType, target, interval, timeout, params, enabled, hasUpdatedAt)
	}
}

func assertOTLPTokenDataPreserved(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	var total int
	if err := pool.QueryRow(ctx, `
SELECT count(*)
  FROM otlp_tokens
 WHERE id IN ($1::uuid, $2::uuid)
`, migrationOTLPTokenA, migrationOTLPTokenB).Scan(&total); err != nil {
		t.Fatalf("count migrated otlp token rows: %v", err)
	}
	if total != 2 {
		t.Fatalf("migrated otlp token rows = %d, want 2", total)
	}
	assertMigratedOTLPToken(ctx, t, pool, migrationOTLPTokenA, migrationTenantA, "tenant-a-token", migrationOTLPHashA)
	assertMigratedOTLPToken(ctx, t, pool, migrationOTLPTokenB, migrationTenantB, "tenant-b-token", migrationOTLPHashB)

	if got := tenantVisibleCount(ctx, t, pool, migrationTenantA, "otlp_tokens", "id IN ($1::uuid, $2::uuid)", migrationOTLPTokenA, migrationOTLPTokenB); got != 1 {
		t.Fatalf("tenant A visible otlp tokens = %d, want 1", got)
	}
	if got := tenantVisibleCount(ctx, t, pool, migrationTenantB, "otlp_tokens", "id IN ($1::uuid, $2::uuid)", migrationOTLPTokenA, migrationOTLPTokenB); got != 1 {
		t.Fatalf("tenant B visible otlp tokens = %d, want 1", got)
	}
	if got := tenantVisibleCount(ctx, t, pool, "", "otlp_tokens", "id IN ($1::uuid, $2::uuid)", migrationOTLPTokenA, migrationOTLPTokenB); got != 0 {
		t.Fatalf("unset-tenant visible otlp tokens = %d, want fail-closed 0", got)
	}

	var hasFK bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1
    FROM pg_constraint
   WHERE conrelid = 'otlp_tokens'::regclass
     AND conname = 'otlp_tokens_tenant_id_fkey'
)
`).Scan(&hasFK); err != nil {
		t.Fatalf("query otlp tenant foreign key: %v", err)
	}
	if !hasFK {
		t.Fatal("otlp_tokens_tenant_id_fkey was not created")
	}

	tenantID := authenticateOTLPTokenAsApp(ctx, t, pool, migrationOTLPHashA)
	if tenantID != migrationTenantA {
		t.Fatalf("otlp_authenticate_token returned tenant %q, want %q", tenantID, migrationTenantA)
	}
	var used bool
	if err := pool.QueryRow(ctx, `
SELECT last_used_at IS NOT NULL
  FROM otlp_tokens
 WHERE id = $1::uuid
`, migrationOTLPTokenA).Scan(&used); err != nil {
		t.Fatalf("query otlp last_used_at: %v", err)
	}
	if !used {
		t.Fatal("otlp_authenticate_token did not preserve/update last_used_at")
	}
}

func assertMigratedOTLPToken(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id, tenantID, name string, tokenHash []byte) {
	t.Helper()

	var gotTenant, gotName string
	var gotHash []byte
	var lastUsedSet, revokedSet bool
	err := pool.QueryRow(ctx, `
SELECT tenant_id::text, name, token_hash, last_used_at IS NOT NULL, revoked_at IS NOT NULL
  FROM otlp_tokens
 WHERE id = $1::uuid
`, id).Scan(&gotTenant, &gotName, &gotHash, &lastUsedSet, &revokedSet)
	if err != nil {
		t.Fatalf("query migrated otlp token %s: %v", id, err)
	}
	if gotTenant != tenantID || gotName != name || string(gotHash) != string(tokenHash) {
		t.Fatalf("migrated otlp token identity = tenant %q name %q hash %q, want tenant %q name %q hash %q", gotTenant, gotName, gotHash, tenantID, name, tokenHash)
	}
	if lastUsedSet || revokedSet {
		t.Fatalf("migrated otlp token optional timestamps changed: last_used=%v revoked=%v", lastUsedSet, revokedSet)
	}
}

func tenantVisibleCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenantID, table, where string, args ...any) int {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tenant visibility check: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		t.Fatalf("assume probectl_app: %v", err)
	}
	if tenantID != "" {
		if _, err := tx.Exec(ctx, "SELECT set_config('probectl.tenant_id', $1, true)", tenantID); err != nil {
			t.Fatalf("set tenant GUC: %v", err)
		}
	}

	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE "+where, args...).Scan(&count); err != nil {
		t.Fatalf("tenant visibility query on %s: %v", table, err)
	}
	return count
}

func authenticateOTLPTokenAsApp(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tokenHash []byte) string {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin otlp auth check: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE probectl_app"); err != nil {
		t.Fatalf("assume probectl_app for otlp auth: %v", err)
	}
	var tenantID string
	if err := tx.QueryRow(ctx, "SELECT tenant_id::text FROM otlp_authenticate_token($1)", tokenHash).Scan(&tenantID); err != nil {
		t.Fatalf("authenticate otlp token as probectl_app: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit otlp auth check: %v", err)
	}
	return tenantID
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
