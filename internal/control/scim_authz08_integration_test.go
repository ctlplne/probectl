// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const scimPatchRemoveMembers = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`

// seedAdminWithMember seeds the system roles and binds a fresh user to the
// Administrator role, returning the admin role id (== its SCIM group id) and
// the member's user id.
func seedAdminWithMember(t *testing.T, db *store.DB, tenant string) (adminRoleID, userID string) {
	t.Helper()
	ctx := context.Background()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.Roles{}).EnsureSystemRoles(ctx, sc); e != nil {
			return e
		}
		admin, e := (store.Roles{}).GetBySlug(ctx, sc, "admin")
		if e != nil {
			return e
		}
		adminRoleID = admin.ID
		u, e := (store.Users{}).Create(ctx, sc, "admin@authz08.test", "Admin08")
		if e != nil {
			return e
		}
		userID = u.ID
		return (store.RoleBindings{}).Bind(ctx, sc, "user", u.ID, admin.ID)
	}); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return adminRoleID, userID
}

func adminMemberCount(t *testing.T, db *store.DB, tenant, roleID string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		members, e := (store.RoleBindings{}).MembersOfRole(ctx, sc, roleID)
		n = len(members)
		return e
	}); err != nil {
		t.Fatalf("count admin members: %v", err)
	}
	return n
}

// AUTHZ-08(1): a SCIM membership PATCH that would empty the Administrator group
// must be refused with 409, not silently lock the tenant out of all admin.
func TestSCIMAdminGroupLastAdminGuardAUTHZ08(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.withSCIMControls(50, 50, 100)
	h := srv.Handler()
	tenant := freshTenant(t, db, "authz08admin")
	adminID, _ := seedAdminWithMember(t, db, tenant)
	tok := scimToken(t, db, tenant, "a")

	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+adminID, tok, scimPatchRemoveMembers)
	if rec.Code != http.StatusConflict {
		t.Fatalf("emptying the admin group must 409, got %d %s", rec.Code, rec.Body)
	}
	if got := adminMemberCount(t, db, tenant, adminID); got == 0 {
		t.Fatal("admin group was emptied despite the 409 (transaction must roll back)")
	}
}

// AUTHZ-08(2): DELETE of a system group must 409 with NO audit row, not a false
// 204 over a group that still exists.
func TestSCIMSystemGroupDeleteConflictNoAuditAUTHZ08(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.withSCIMControls(50, 50, 100)
	h := srv.Handler()
	tenant := freshTenant(t, db, "authz08del")
	adminID, _ := seedAdminWithMember(t, db, tenant)
	tok := scimToken(t, db, tenant, "a")

	rec := scimReq(t, h, http.MethodDelete, "/scim/v2/Groups/"+adminID, tok, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("system-group DELETE must 409, got %d %s", rec.Code, rec.Body)
	}
	audits := countTenantRows(t, db, tenant,
		`SELECT count(*) FROM audit_events WHERE action = 'directory.group_delete' AND target = $1`, adminID)
	if audits != 0 {
		t.Fatalf("a refused delete must write no audit row, got %d", audits)
	}
	// The group still resolves.
	if get := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+adminID, tok, ""); get.Code != http.StatusOK {
		t.Fatalf("admin group must still exist after a refused delete, got %d %s", get.Code, get.Body)
	}
}

// AUTHZ-08(3): a suspended or offboarding tenant must not provision over SCIM.
// Each case uses a fresh tenant so the first status read is the one under test
// (the status cache's default TTL is 15s; reading "active" first would mask a
// later suspension within the window).
func TestSCIMSuspendedTenantForbiddenAUTHZ08(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.withSCIMControls(50, 50, 100)
	h := srv.Handler()
	ctx := context.Background()

	// Active tenant is served.
	active := freshTenant(t, db, "authz08active")
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", scimToken(t, db, active, "a"), ""); rec.Code != http.StatusOK {
		t.Fatalf("active tenant SCIM must be 200, got %d %s", rec.Code, rec.Body)
	}

	for _, status := range []string{"suspended", "offboarding"} {
		tenant := freshTenant(t, db, "authz08"+status)
		tok := scimToken(t, db, tenant, "a")
		if _, err := store.NewTenants(db.Pool()).UpdateStatus(ctx, tenant, status); err != nil {
			t.Fatalf("set %s: %v", status, err)
		}
		rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", tok, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s tenant SCIM must 403, got %d %s", status, rec.Code, rec.Body)
		}
	}
}

// AUTHZ-08(4): an expired SCIM token must 401.
func TestSCIMExpiredTokenUnauthorizedAUTHZ08(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.withSCIMControls(50, 50, 100)
	h := srv.Handler()
	ctx := context.Background()
	tenant := freshTenant(t, db, "authz08exp")
	live := scimToken(t, db, tenant, "live")
	expiring := scimToken(t, db, tenant, "expiring")

	// Expire one token in the past (any mechanism that sets expires_at).
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := sc.Q.Exec(ctx, `UPDATE scim_tokens SET expires_at = now() - interval '1 hour' WHERE name = 'expiring'`)
		return e
	}); err != nil {
		t.Fatalf("expire token: %v", err)
	}

	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", expiring, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token must 401, got %d %s", rec.Code, rec.Body)
	}
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", live, ""); rec.Code != http.StatusOK {
		t.Fatalf("live token must 200, got %d %s", rec.Code, rec.Body)
	}
}

// AUTHZ-08(5): an unauthenticated token must be rejected at AUTH, before the
// rate limiter — so flooding unknown tokens never populates (or, past 4096,
// wipes) the shared bucket map and resets a valid tenant's throttle. Before the
// fix the limiter ran first, keyed by the raw token hash, so a repeated unknown
// token consumed a bucket and returned 429 instead of 401.
func TestSCIMRateLimitNotResetByUnknownTokensAUTHZ08(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.withSCIMControls(100, 100, 1) // rate 1/min
	h := srv.Handler()
	tenant := freshTenant(t, db, "authz08rl")
	tok := scimToken(t, db, tenant, "valid")

	// A repeated unknown token is 401 both times (never limited pre-auth).
	for i := 0; i < 2; i++ {
		rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", "bogus-token-xyz", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unknown token req %d must 401 (not limited pre-auth), got %d %s", i, rec.Code, rec.Body)
		}
	}
	// The valid tenant's throttle is intact: first OK, second 429.
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", tok, ""); rec.Code != http.StatusOK {
		t.Fatalf("valid token first request must 200, got %d %s", rec.Code, rec.Body)
	}
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", tok, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("valid token must still be throttled (429) — unknown-token flood must not reset it, got %d %s", rec.Code, rec.Body)
	}
}
