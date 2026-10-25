// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && !probectl_core

package main

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DPR-324 (D-62 option c): a siloed or hybrid tenant pinned to a plane that
// PROBECTL_DATAPLANES no longer names refuses startup, naming the tenant and
// the plane, instead of being routed to the default plane. Deleted tenants,
// pooled tenants and tenants on the default plane never block it.
func TestSiloResidencyPreflightRefusesAMissingPlane(t *testing.T) {
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
		t.Cleanup(func() { _, _ = db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, id) })
		return id
	}
	pinned := mk("rp-mars", "hybrid", "offboarding", "mars-"+stamp)
	deleted := mk("rp-deleted", "siloed", "deleted", "venus-"+stamp)
	pooled := mk("rp-pooled", "pooled", "active", "venus-"+stamp)
	home := mk("rp-home", "siloed", "active", "")

	planes := []string{"eu"}
	missing, err := isolatedTenantsOffPlane(ctx, db.Pool(), planes)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(missing, ",")
	if !strings.Contains(joined, pinned+" (mars-"+stamp+")") {
		t.Fatalf("a tenant pinned to an unconfigured plane was not reported: %v", missing)
	}
	for _, id := range []string{deleted, pooled, home} {
		if strings.Contains(joined, id) {
			t.Fatalf("tenant %s cannot be misrouted and must not block startup: %v", id, missing)
		}
	}
	if err := siloResidencyPreflight(ctx, db.Pool(), planes); err == nil || !strings.Contains(err.Error(), pinned) || !strings.Contains(err.Error(), "DPR-324") {
		t.Fatalf("preflight = %v, want startup refused naming the tenant", err)
	}
	planes = append(planes, "mars-"+stamp)
	missing, err = isolatedTenantsOffPlane(ctx, db.Pool(), planes)
	if err != nil || strings.Contains(strings.Join(missing, ","), pinned) {
		t.Fatalf("with its plane restored the tenant must pass: %v %v", missing, err)
	}
}

type fakeSchemaVerifier struct{ missing map[string][]string }

func (f fakeSchemaVerifier) MissingSiloTables(_ context.Context, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, id := range ids {
		if m := f.missing[id]; len(m) > 0 {
			out[id] = m
		}
	}
	return out, nil
}

// DPR-385 (stop mode): startup refuses when a siloed tenant's schema still
// lacks a tenant-owned table after the catch-up, naming the tenant and the
// table; an offboarding silo (not caught up) is left to InTenant's guard.
func TestSiloSchemasCompleteRefusesAnIncompleteSilo(t *testing.T) {
	db := setupBootstrapAdminDB(t)
	ctx := context.Background()
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	mk := func(slug, status string) string {
		t.Helper()
		var id string
		if err := db.Pool().QueryRow(ctx, `INSERT INTO tenants (slug, name, isolation_model, residency, status)
			VALUES ($1, $1, 'siloed', '', $2) RETURNING id::text`, slug+"-"+stamp, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, id) })
		return id
	}
	hollow, leaving := mk("sc-hollow", "active"), mk("sc-leaving", "offboarding")
	err := siloSchemasComplete(ctx, db.Pool(), fakeSchemaVerifier{missing: map[string][]string{hollow: {"tests"}, leaving: {"tests"}}})
	if err == nil || !strings.Contains(err.Error(), hollow) || !strings.Contains(err.Error(), "tests") || strings.Contains(err.Error(), leaving) {
		t.Fatalf("siloSchemasComplete = %v, want startup refused naming %s's missing table only", err, hollow)
	}
	if err := siloSchemasComplete(ctx, db.Pool(), fakeSchemaVerifier{}); err != nil {
		t.Fatalf("complete silos refused: %v", err)
	}
}
