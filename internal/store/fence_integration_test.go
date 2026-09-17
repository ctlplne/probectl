// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFenceWritesMakesEverySessionReadOnly (DPR-089): while the cluster
// manager fences the writer pool, every session it hands out is read-only —
// a write from any code path fails closed with SQLSTATE 25006, exactly the
// failure a standby produces — reads keep serving, and releasing the fence
// recycles the sessions so writes flow again without a restart.
func TestFenceWritesMakesEverySessionReadOnly(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, dsn(), 4, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	pool := db.Pool()
	table := fmt.Sprintf("fence_probe_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE TABLE "+table+" (id int)"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	defer func() { _, _ = pool.Exec(ctx, "DROP TABLE IF EXISTS "+table) }()

	if !db.FenceWrites(true) {
		t.Fatal("the first fence must report a change")
	}
	if db.FenceWrites(true) {
		t.Fatal("re-fencing must be a no-op")
	}
	if !db.WritesFenced() {
		t.Fatal("WritesFenced must report the fence")
	}

	// Plain statements and transactions alike: fenced sessions refuse writes.
	_, err = pool.Exec(ctx, "INSERT INTO "+table+" VALUES (1)")
	assertReadOnlyRefusal(t, "insert while fenced", err)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin while fenced: %v", err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO "+table+" VALUES (2)")
	assertReadOnlyRefusal(t, "insert in a transaction while fenced", err)
	_ = tx.Rollback(ctx)

	// Reads keep serving.
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
		t.Fatalf("read while fenced: n=%d err=%v", n, err)
	}

	// Releasing the fence recycles the sessions: writes flow again.
	if !db.FenceWrites(false) {
		t.Fatal("releasing the fence must report a change")
	}
	if _, err := pool.Exec(ctx, "INSERT INTO "+table+" VALUES (3)"); err != nil {
		t.Fatalf("write after the fence was released: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly the post-release write must land: n=%d err=%v", n, err)
	}
}

func assertReadOnlyRefusal(t *testing.T, what string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "25006" {
		t.Fatalf("%s: expected read_only_sql_transaction (SQLSTATE 25006), got %v", what, err)
	}
}
