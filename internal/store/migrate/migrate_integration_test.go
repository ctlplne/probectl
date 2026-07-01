// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
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
		t.Skipf("no database available: %v", err)
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
		t.Skipf("no database available: %v", err)
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
		t.Skipf("no database available: %v", err)
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
