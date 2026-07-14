// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package testsupport

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const postgresPublicCatalogTestLock = "probectl:test:postgres-public-catalog"

// LockPostgresPublicCatalog serializes integration tests that temporarily
// mutate the shared public schema with tests that enumerate its live
// tenant-owned tables. Go runs package test binaries concurrently, so unique
// table names alone do not prevent an enumerator from observing a table just
// before its owning package drops it.
//
// PostgreSQL advisory locks are session-scoped. The helper therefore reserves
// one pool connection until test cleanup, explicitly unlocks it, and reports
// both lock and unlock failures instead of turning coordination loss into a
// flaky green.
func LockPostgresPublicCatalog(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire Postgres public-catalog test lock connection: %v", err)
	}
	if _, err := conn.Exec(ctx,
		`SELECT pg_advisory_lock(hashtextextended($1, 0))`, postgresPublicCatalogTestLock); err != nil {
		conn.Release()
		t.Fatalf("lock Postgres public catalog for integration test: %v", err)
	}
	t.Cleanup(func() {
		var unlocked bool
		err := conn.QueryRow(context.Background(),
			`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, postgresPublicCatalogTestLock).Scan(&unlocked)
		conn.Release()
		if err != nil {
			t.Errorf("unlock Postgres public catalog after integration test: %v", err)
		} else if !unlocked {
			t.Error("unlock Postgres public catalog after integration test: lock was not held")
		}
	})
}
