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
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestApplyRepairsInvalidIndexRecordedAsApplied is the PLAT-03 regression: a
// CREATE INDEX CONCURRENTLY interrupted by a deadlock/crash leaves an index with
// indisvalid=false while the ledger records the migration as applied. On a later
// boot CREATE INDEX CONCURRENTLY IF NOT EXISTS SKIPS the leftover, so the schema
// stays broken forever (e.g. 0098 => every incident-signal insert fails). Apply
// must now detect and rebuild such an index under the advisory lock.
//
// It builds the invalid index deterministically (a UNIQUE CIC over duplicate
// data fails and leaves it invalid), de-duplicates so the rebuild can succeed,
// records the migration as applied, then runs Apply and asserts the index is
// valid. On the pre-fix tree Apply skips the recorded migration and the index
// stays invalid, so the assertion goes red.
func TestApplyRepairsInvalidIndexRecordedAsApplied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	table := fmt.Sprintf("plat03_t_%d", suffix)
	index := fmt.Sprintf("%s_uidx", table)
	version := suffix

	defer func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table+" CASCADE")
		_, _ = pool.Exec(context.Background(), "DELETE FROM schema_migrations WHERE version = $1", version)
	}()

	// Build an INVALID index: a UNIQUE CIC over duplicate rows fails and leaves
	// the index behind with indisvalid=false.
	mustExec(ctx, t, pool, "CREATE TABLE "+table+" (id int)")
	mustExec(ctx, t, pool, "INSERT INTO "+table+" VALUES (1),(1)")
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE UNIQUE INDEX CONCURRENTLY %s ON %s (id)", index, table)); err == nil {
		t.Fatal("unique CIC over duplicate rows unexpectedly succeeded; cannot stage an invalid index")
	}
	if valid := indexValid(ctx, t, pool, index); valid {
		t.Fatalf("staged index %s is valid; the invalid-index precondition did not hold", index)
	}
	// De-duplicate so the rebuild can succeed, then record the migration as
	// applied — simulating the wedge where the ledger says done but the index is
	// invalid.
	mustExec(ctx, t, pool, fmt.Sprintf("DELETE FROM %s a USING %s b WHERE a.ctid < b.ctid AND a.id = b.id", table, table))
	mustExec(ctx, t, pool, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", version, "plat03_repair")

	fsys := fstest.MapFS{
		fmt.Sprintf("%d_plat03_repair.sql", version): {Data: []byte(fmt.Sprintf(
			"-- probectl:no-tx: CREATE INDEX CONCURRENTLY cannot run inside a transaction\n"+
				"CREATE TABLE IF NOT EXISTS %s (id int);\n"+
				"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS %s ON %s (id);\n", table, index, table))},
	}

	if _, err := migrate.New(fsys, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply (with repair): %v", err)
	}

	if !indexValid(ctx, t, pool, index) {
		t.Fatalf("index %s is still INVALID after Apply; a CIC left invalid and recorded as applied was not repaired (PLAT-03)", index)
	}
}

func mustExec(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func indexValid(ctx context.Context, t *testing.T, pool *pgxpool.Pool, index string) bool {
	t.Helper()
	var valid bool
	err := pool.QueryRow(ctx, `SELECT i.indisvalid
		FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname = $1`, index).Scan(&valid)
	if err != nil {
		return false // absent counts as not-valid
	}
	return valid
}
