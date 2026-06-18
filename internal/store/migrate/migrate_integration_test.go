// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package migrate_test

import (
	"context"
	"fmt"
	"os"
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
