// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package migrate_test

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ctlplne/probectl/internal/store/migrate"
)

func TestApplyPreservesIndexesOutsideMigrationOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	pool := ownedMigrationPool(ctx, t)
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	indexOID := func(name string) int64 {
		t.Helper()
		var oid int64
		if err := pool.QueryRow(ctx, "SELECT COALESCE(to_regclass($1)::oid::bigint,0)", name).Scan(&oid); err != nil {
			t.Fatal(err)
		}
		return oid
	}
	exec("CREATE TABLE public.owned_rows (id int)")
	exec("CREATE INDEX managed_idx ON public.owned_rows (id)")
	for _, schema := range []string{"public", "tenant_a", "tenant_b"} {
		if schema != "public" {
			exec("CREATE SCHEMA " + schema)
		}
		exec("CREATE TABLE " + schema + ".unmanaged_rows (id int)")
		exec("INSERT INTO " + schema + ".unmanaged_rows VALUES (1),(1)")
		index := "managed_idx"
		if schema == "public" {
			index = "unmanaged_idx"
		}
		if _, err := pool.Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY "+index+" ON "+schema+".unmanaged_rows (id)"); err == nil {
			t.Fatal("duplicate rows did not leave the required invalid index")
		}
	}
	names := []string{"public.managed_idx", "public.unmanaged_idx", "tenant_a.managed_idx", "tenant_b.managed_idx"}
	original := map[string]int64{}
	for _, name := range names {
		original[name] = indexOID(name)
		if original[name] == 0 {
			t.Fatal("required original index missing", name)
		}
	}
	exec("CREATE TABLE schema_migrations (version bigint PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())")
	exec("INSERT INTO schema_migrations (version,name) VALUES (100,'owned')")
	fsys := fstest.MapFS{
		"0100_owned.sql":   {Data: []byte("-- probectl:no-tx: concurrent index\nCREATE INDEX CONCURRENTLY IF NOT EXISTS managed_idx ON public.owned_rows (id);")},
		"0101_pending.sql": {Data: []byte("-- probectl:no-tx: independent pending work\nSELECT 1;")},
	}
	if _, err := migrate.New(fsys, nil).Apply(ctx, pool); err != nil {
		t.Error("unrelated invalid indexes blocked independent migration:", err)
	}
	for _, name := range names {
		if got := indexOID(name); got != original[name] {
			t.Error("migration recovery deleted or rebuilt an index outside its repair authority", name, "original_oid", original[name], "current_oid", got)
		}
	}
}
