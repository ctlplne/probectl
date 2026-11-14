// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package migrate_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestConcurrentApplyIsDeadlockFree keeps six simultaneous appliers on one
// database, including the original no-tx concurrent-index race. Nonblocking
// advisory-lock polling must avoid holding a snapshot that deadlocks CIC.
// The owned database excludes unrelated suites' snapshots and catalog traffic;
// the concurrency, deadline and final valid-index assertion remain unchanged.
func TestConcurrentApplyIsDeadlockFree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := ownedMigrationPool(ctx, t)
	suffix := time.Now().UnixNano()
	table := fmt.Sprintf("tq02_concurrent_%d", suffix)
	index := table + "_value_idx"
	defer func() { _, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table) }()

	fsys := fstest.MapFS{
		fmt.Sprintf("%d_create.sql", suffix): {Data: []byte(
			fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id bigint PRIMARY KEY, value text);", table))},
		fmt.Sprintf("%d_index.sql", suffix+1): {Data: []byte(
			fmt.Sprintf("-- probectl:no-tx: CREATE INDEX CONCURRENTLY cannot run in a migration transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS %s ON %s (value);", index, table))},
	}

	// Six appliers still compete for the same session lock and build the same
	// concurrent index. Other packages cannot hold snapshots of this database.
	const n = 6
	var gate sync.WaitGroup
	gate.Add(1)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			gate.Wait()
			_, e := migrate.New(fsys, nil).Apply(ctx, pool)
			errs <- e
		}()
	}
	gate.Done()
	for i := 0; i < n; i++ {
		if e := <-errs; e != nil {
			msg := e.Error()
			if strings.Contains(msg, "40P01") || strings.Contains(strings.ToLower(msg), "deadlock") {
				t.Fatalf("TQ-02: concurrent Apply deadlocked: %v", e)
			}
			t.Fatalf("concurrent Apply errored: %v", e)
		}
	}

	var valid bool
	if err := pool.QueryRow(ctx, `
SELECT i.indisvalid
  FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
 WHERE c.relname = $1`, index).Scan(&valid); err != nil {
		t.Fatalf("TQ-02: concurrent index %q not found after concurrent apply: %v", index, err)
	}
	if !valid {
		t.Fatalf("TQ-02: concurrent index %q is INVALID after concurrent apply", index)
	}
}

func ownedMigrationPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin, err := pgxpool.New(ctx, concurrentDSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}

	suffix := time.Now().UnixNano()
	// Compete with six appliers on the same database, without inheriting
	// unrelated packages' public-catalog work or their long-lived snapshots.
	// Advisory locking and the no-tx CIC still exercise the original race.
	database := fmt.Sprintf("probectl_qa_beta_migrate_%d", suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		testsupport.SkipOrFatal(t, "dedicated migration proof requires QA CREATE DATABASE privilege: %v", err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Error("drop owned migration proof database:", err)
		}
	})
	settings := admin.Config()
	settings.ConnConfig.Database = database
	pool, err = pgxpool.NewWithConfig(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

// concurrentDSN resolves the test Postgres DSN without depending on the
// integration-only dsn() helper (migrate_integration_test.go), so this
// regression also compiles and runs under -tags=isolation. Same resolution
// order as dsn(): PROBECTL_DATABASE_URL, then the local default.
func concurrentDSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
}
