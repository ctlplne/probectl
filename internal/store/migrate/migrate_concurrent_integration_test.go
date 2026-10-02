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
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestConcurrentApplyIsDeadlockFree is the TQ-02 regression. The cross-tenant
// isolation gate runs its packages in parallel, and each applied migrations on
// a fresh database at once. Without a serializing lock, a blocking advisory lock
// held an open snapshot while a peer's CREATE INDEX CONCURRENTLY waited on it —
// deadlocking (40P01) and non-deterministically wedging the gate. PLAT-03's
// pg_try_advisory_lock + backoff makes concurrent Apply serialize safely; this
// proves it under contention, including a no-tx CONCURRENTLY index (the exact
// statement that used to deadlock), and that the resulting index is VALID.
func TestConcurrentApplyIsDeadlockFree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	table := fmt.Sprintf("tq02_concurrent_%d", suffix)
	index := table + "_value_idx"
	defer func() { _, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table) }()

	fsys := fstest.MapFS{
		fmt.Sprintf("%d_create.sql", suffix): {Data: []byte(
			fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id bigint PRIMARY KEY, value text);", table))},
		fmt.Sprintf("%d_index.sql", suffix+1): {Data: []byte(
			fmt.Sprintf("-- probectl:no-tx: CREATE INDEX CONCURRENTLY cannot run in a migration transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS %s ON %s (value);", index, table))},
	}

	// Release all appliers at once to maximize contention on the global
	// migration advisory lock (what parallel isolation packages do).
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

	// The CONCURRENTLY-built index must be present AND valid (a crashed/deadlocked
	// CIC leaves an INVALID index that silently breaks the schema).
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
