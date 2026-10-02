// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func cmdbKeysIsolationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testsupport.PostgresDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// TestCMDBKeysOwnershipIsolation is the AUTHZ-17 regression (G7.1, TENANT
// ISOLATION). The CMDB is ONE deployment-level system shared by every tenant.
// The ownership check (store.CMDBKeys.TenantOwns) is the gate that decides
// whether a tenant may resolve a given key out of that shared CMDB, so it MUST
// answer for the AUTHORITATIVE tenant (the authenticated request principal,
// carried on tenancy.Scope.Tenant) and never for a self-asserted agent
// name/hostname that happens to collide across tenants.
//
// The attack: tenant A owns an agent "edge-1" (so A's CI for that key is A's to
// read). An operator in tenant B renames/points one of its own assets at the
// same name "edge-1" hoping the ownership gate will wave it through and hand it
// A's configuration item. Before the fix the ownership query matched the key by
// name with no tenant_id predicate and leaned entirely on RLS; run on a
// connection that is not RLS-scoped to B it saw A's row and returned true — a
// cross-tenant read. After the fix every EXISTS is bound to tenant_id =
// s.Tenant, so B's ownership is computed strictly from B's own rows: the key
// "edge-1" is not-owned for B (→ the handler's 404) even though that name
// exists elsewhere in the deployment.
//
// This runs the REAL CMDBKeys store against real Postgres with two tenants. The
// scope's Querier is the raw pool, which (as the migrating superuser) is not
// confined by RLS — exactly the condition under which the storage-layer tenant
// predicate, not RLS context, has to hold the boundary (defense in depth).
func TestCMDBKeysOwnershipIsolation(t *testing.T) {
	ctx := context.Background()
	pool := cmdbKeysIsolationPool(t)
	defer pool.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA, err := NewTenants(pool).Create(ctx, "cmdb-a-"+suffix, "CMDB A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, "cmdb-b-"+suffix, "CMDB B")
	if err != nil {
		t.Fatal(err)
	}

	// Tenant A owns the agent "edge-1"; tenant B owns a different agent of its
	// own. (Inserted via the raw pool so the rows exist regardless of RLS — the
	// point of the test is that the ownership QUERY, not the connection, scopes
	// by tenant.)
	seedAgent := func(tenantID, name, hostname string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (tenant_id, name, hostname) VALUES ($1, $2, $3)`,
			tenantID, name, hostname); err != nil {
			t.Fatalf("seed agent %s/%s: %v", tenantID, name, err)
		}
	}
	seedAgent(tenantA.ID, "edge-1", "edge-1")
	seedAgent(tenantB.ID, "edge-probe", "edge-probe")

	owns := func(tenantID, key string) bool {
		t.Helper()
		got, err := (CMDBKeys{}).TenantOwns(ctx, tenancy.Scope{
			Tenant: tenancy.ID(tenantID), Q: pool,
		}, key)
		if err != nil {
			t.Fatalf("TenantOwns(%s, %q): %v", tenantID, key, err)
		}
		return got
	}

	// THE boundary assertion (AUTHZ-17): tenant B must NOT own tenant A's key
	// "edge-1" just because that name exists in the shared deployment. Before the
	// fix this returned true (the predicate-free query saw A's row on the
	// non-RLS connection) — a cross-tenant CI read. It must be false.
	if owns(tenantB.ID, "edge-1") {
		t.Fatal("AUTHZ-17: tenant B owns tenant A's CMDB key \"edge-1\" " +
			"(cross-tenant read: a renamed/colliding agent name crossed the tenant boundary)")
	}

	// Positive controls: the scoping must not over-restrict. Each tenant still
	// owns its OWN keys, and neither can see the other's.
	if !owns(tenantA.ID, "edge-1") {
		t.Fatal("tenant A must own its own agent key \"edge-1\"")
	}
	if !owns(tenantB.ID, "edge-probe") {
		t.Fatal("tenant B must own its own agent key \"edge-probe\"")
	}
	if owns(tenantA.ID, "edge-probe") {
		t.Fatal("tenant A must not own tenant B's agent key \"edge-probe\"")
	}

	// No tenant in scope → fail closed (owns nothing), never a predicate-free
	// match against the whole deployment.
	if got, err := (CMDBKeys{}).TenantOwns(ctx, tenancy.Scope{Q: pool}, "edge-1"); err != nil || got {
		t.Fatalf("empty tenant scope must own nothing, got owns=%v err=%v", got, err)
	}
}
