// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && !probectl_core

package main

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"
)

type recordingReaderCatchUp struct{ seen map[string]string }

func (r *recordingReaderCatchUp) CatchUpReaderScope(_ context.Context, tenantID, residency string) error {
	r.seen[tenantID] = residency
	return nil
}

// The boot reader-scope catch-up proves every siloed/hybrid tenant the router
// can still send a read to (offboarding included) and skips deleted tenants,
// whose databases were erased, and pooled tenants, which have none.
func TestSiloReaderCatchUpSkipsDeletedTenants(t *testing.T) {
	db := setupBootstrapAdminDB(t)
	ctx := context.Background()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	mk := func(slug, model, status, residency string) string {
		t.Helper()
		var id string
		if err := db.Pool().QueryRow(ctx, `INSERT INTO tenants (slug, name, isolation_model, residency, status, audit_write_fenced_at)
			VALUES ($1, $1, $2, $3, $4, CASE WHEN $4 = 'deleted' THEN now() END) RETURNING id::text`,
			slug+"-"+stamp, model, residency, status).Scan(&id); err != nil {
			t.Fatalf("tenant %s: %v", slug, err)
		}
		// Leave no routable silo behind in the shared integration database:
		// a later boot there would try to prove it.
		t.Cleanup(func() { _, _ = db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, id) })
		return id
	}
	active := mk("rdr-cu-active", "siloed", "active", "eu")
	offboarding := mk("rdr-cu-off", "hybrid", "offboarding", "")
	deleted := mk("rdr-cu-deleted", "siloed", "deleted", "eu")
	pooled := mk("rdr-cu-pooled", "pooled", "active", "")

	rec := &recordingReaderCatchUp{seen: map[string]string{}}
	if err := siloReaderCatchUpAll(ctx, db.Pool(), rec, true, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if got, ok := rec.seen[active]; !ok || got != "eu" {
		t.Errorf("the active siloed tenant was not proven on its plane (seen %q, %v)", got, ok)
	}
	if _, ok := rec.seen[offboarding]; !ok {
		t.Error("an offboarding hybrid tenant is still routable and must be proven")
	}
	if _, ok := rec.seen[deleted]; ok {
		t.Error("a deleted tenant's erased silo was proven at boot")
	}
	if _, ok := rec.seen[pooled]; ok {
		t.Error("a pooled tenant has no per-tenant database to prove")
	}
}
