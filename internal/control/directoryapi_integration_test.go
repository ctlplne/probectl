// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// directoryPrincipal creates a user holding exactly the given permissions and
// returns a bearer token for it (the narrow-role principal the RBAC checks
// need; the dev-mode tenant header would grant everything).
func directoryPrincipal(t *testing.T, db *store.DB, tenant, email string, perms ...string) (userID, token string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).CreateSCIM(ctx, sc, store.User{Email: email, UserName: email})
		if err != nil {
			return err
		}
		userID = u.ID
		role, err := (store.Roles{}).Create(ctx, sc, "svc-"+strings.SplitN(email, "@", 2)[0], "svc", "")
		if err != nil {
			return err
		}
		for _, p := range perms {
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, p); err != nil {
				return err
			}
		}
		return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID)
	}); err != nil {
		t.Fatalf("principal %s: %v", email, err)
	}
	tok, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(db.Pool()).Create(context.Background(), tenant, userID, "directory-test", crypto.Hash([]byte(tok))); err != nil {
		t.Fatalf("bearer token: %v", err)
	}
	return userID, tok
}

func seedTenantRoles(t *testing.T, db *store.DB, tenant string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	roles := [][2]string{{"admin", "Administrator"}, {"editor", "Editor"}, {"viewer", "Viewer"}}
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		for _, r := range roles {
			if _, err := (store.Roles{}).Create(ctx, sc, r[0], r[1], ""); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
}

func bearerReq(t *testing.T, h http.Handler, method, path, tenant, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = strings.NewReader(string(b))
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Probectl-Tenant", tenant)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func auditCount(t *testing.T, db *store.DB, tenant, action string) int {
	t.Helper()
	var n int
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, tenant, action).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}

// DPR-027: a tenant administrator manages people and roles inside the tenant
// boundary; a narrow reader cannot; a foreign tenant sees nothing; the last
// administrator cannot be removed; every mutation is audited.
func TestDirectoryUsersAndRolesAreTenantScopedAuditedAndGuarded(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenantA := freshTenant(t, db, "dir-a")
	tenantB := freshTenant(t, db, "dir-b")
	seedTenantRoles(t, db, tenantA)
	seedTenantRoles(t, db, tenantB)
	_, adminTok := directoryPrincipal(t, db, tenantA, "dir-admin@example.com", permDirectoryRead, permDirectoryWrite)
	_, readerTok := directoryPrincipal(t, db, tenantA, "dir-reader@example.com", permDirectoryRead)
	_, adminBTok := directoryPrincipal(t, db, tenantB, "dir-admin-b@example.com", permDirectoryRead, permDirectoryWrite)

	// A narrow reader lists but cannot create.
	if rec := bearerReq(t, h, http.MethodGet, "/v1/directory/users", tenantA, readerTok, nil); rec.Code != http.StatusOK {
		t.Fatalf("reader list = %d: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenantA, readerTok, map[string]any{"email": "x@example.com"}); rec.Code != http.StatusForbidden {
		t.Fatalf("reader create = %d, want 403: %s", rec.Code, rec.Body)
	}

	// Roles list carries permissions and member counts.
	rolesRec := bearerReq(t, h, http.MethodGet, "/v1/directory/roles", tenantA, adminTok, nil)
	if rolesRec.Code != http.StatusOK || !strings.Contains(rolesRec.Body.String(), `"slug":"editor"`) || !strings.Contains(rolesRec.Body.String(), `"permissions"`) {
		t.Fatalf("roles = %d: %s", rolesRec.Code, rolesRec.Body)
	}

	// Create a teammate before first login with a role in one audited step.
	create := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenantA, adminTok, map[string]any{
		"email": "New.Hire@Example.com", "display_name": "New Hire", "role": "editor",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body)
	}
	var hire struct {
		ID    string   `json:"id"`
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &hire); err != nil {
		t.Fatal(err)
	}
	if hire.Email != "new.hire@example.com" || strings.Join(hire.Roles, ",") != "editor" {
		t.Fatalf("created user = %+v, want lower-cased email with editor", hire)
	}
	if dup := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenantA, adminTok, map[string]any{"email": "new.hire@example.com"}); dup.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409: %s", dup.Code, dup.Body)
	}
	if bad := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenantA, adminTok, map[string]any{"email": "a@example.com", "role": "nope"}); bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown role = %d, want 422: %s", bad.Code, bad.Body)
	}

	// The tenant listing shows the hire with the editor role.
	list := bearerReq(t, h, http.MethodGet, "/v1/directory/users", tenantA, adminTok, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"email":"new.hire@example.com"`) || !strings.Contains(list.Body.String(), `"roles":["editor"]`) {
		t.Fatalf("list = %d: %s", list.Code, list.Body)
	}

	// Tenant isolation: B never sees or reaches A's user, even by id.
	if rec := bearerReq(t, h, http.MethodGet, "/v1/directory/users", tenantB, adminBTok, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "new.hire@example.com") {
		t.Fatalf("tenant B list leaked tenant A: %d %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+hire.ID+"/roles", tenantB, adminBTok, map[string]any{"role": "admin"}); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant bind = %d, want 404: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+hire.ID+"/roles/editor", tenantB, adminBTok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant unbind = %d, want 404: %s", rec.Code, rec.Body)
	}

	// Bind is idempotent; unbind removes; the roles reflect it.
	for range 2 {
		if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+hire.ID+"/roles", tenantA, adminTok, map[string]any{"role": "viewer"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"roles":["editor","viewer"]`) {
			t.Fatalf("bind viewer = %d: %s", rec.Code, rec.Body)
		}
	}
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+hire.ID+"/roles/viewer", tenantA, adminTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unbind viewer = %d: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+hire.ID+"/roles", tenantA, readerTok, map[string]any{"role": "viewer"}); rec.Code != http.StatusForbidden {
		t.Fatalf("reader bind = %d, want 403", rec.Code)
	}

	// The last administrator of the tenant cannot be removed.
	if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+hire.ID+"/roles", tenantA, adminTok, map[string]any{"role": "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("bind admin = %d: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+hire.ID+"/roles/admin", tenantA, adminTok, nil); rec.Code != http.StatusConflict {
		t.Fatalf("removing the only admin = %d, want 409: %s", rec.Code, rec.Body)
	}
	second := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenantA, adminTok, map[string]any{"email": "second.admin@example.com", "role": "admin"})
	if second.Code != http.StatusCreated {
		t.Fatalf("second admin = %d: %s", second.Code, second.Body)
	}
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+hire.ID+"/roles/admin", tenantA, adminTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("removing one of two admins = %d: %s", rec.Code, rec.Body)
	}

	// Every mutation reached the tenant audit stream, none reached tenant B.
	for action, want := range map[string]int{"directory.user_create": 2, "directory.role_bind": 3, "directory.role_unbind": 2} {
		if got := auditCount(t, db, tenantA, action); got != want {
			t.Errorf("audit %s in tenant A = %d, want %d", action, got, want)
		}
		if got := auditCount(t, db, tenantB, action); got != 0 {
			t.Errorf("audit %s leaked into tenant B: %d", action, got)
		}
	}
}

// TestDirectoryDelegatesARoleToOneBranchOfTheHierarchy: delegated
// administration is a role bound at an org, team or project scope, which RBAC
// honors only inside that branch (Principal.HasAt) and never tenant-wide. The
// model, the hierarchy checks and docs/scim-abac.md all had it, but no
// operator path could create such a grant. A tenant administrator now grants
// and revokes one through the directory API, it shows in the listing, it lets
// its holder administer exactly that branch, it never counts as a tenant
// administrator, and a foreign tenant's branch cannot be named.
func TestDirectoryDelegatesARoleToOneBranchOfTheHierarchy(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenantA, tenantB := freshTenant(t, db, "deleg-a"), freshTenant(t, db, "deleg-b")
	for _, tenant := range []string{tenantA, tenantB} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).EnsureSystemRoles(ctx, sc)
		}); err != nil {
			t.Fatalf("seed system roles: %v", err)
		}
	}
	_, adminTok := directoryPrincipal(t, db, tenantA, "deleg-admin@example.com", permDirectoryRead, permDirectoryWrite, permOrgRead, permOrgWrite)
	_, adminBTok := directoryPrincipal(t, db, tenantB, "deleg-admin-b@example.com", permDirectoryRead, permDirectoryWrite)

	// The tenant's one tenant-wide administrator, through the same API.
	created := func(tok, tenant, email, role string) directoryUser {
		t.Helper()
		body := map[string]any{"email": email}
		if role != "" {
			body["role"] = role
		}
		rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users", tenant, tok, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %s = %d: %s", email, rec.Code, rec.Body)
		}
		var u directoryUser
		if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	owner := created(adminTok, tenantA, "deleg-owner@example.com", "admin")
	dana := created(adminTok, tenantA, "deleg-dana@example.com", "")
	org := func(slug, name string) string {
		t.Helper()
		rec := bearerReq(t, h, http.MethodPost, "/v1/hierarchy/orgs", tenantA, adminTok, map[string]string{"slug": slug, "name": name})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create org %s = %d: %s", slug, rec.Code, rec.Body)
		}
		var o struct{ ID string }
		if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		return o.ID
	}
	alpha, beta := org("alpha", "Alpha"), org("beta", "Beta")

	// Validation: an unknown scope type, a scope id without a branch type, and a
	// branch that is not this tenant's are all refused.
	for _, bad := range []struct {
		body map[string]any
		code int
	}{
		{map[string]any{"role": "admin", "scope_type": "galaxy", "scope_id": alpha}, http.StatusUnprocessableEntity},
		{map[string]any{"role": "admin", "scope_type": "org"}, http.StatusUnprocessableEntity},
		{map[string]any{"role": "admin", "scope_id": alpha}, http.StatusUnprocessableEntity},
	} {
		if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+dana.ID+"/roles", tenantA, adminTok, bad.body); rec.Code != bad.code {
			t.Fatalf("grant %v = %d, want %d: %s", bad.body, rec.Code, bad.code, rec.Body)
		}
	}

	// Delegate org Alpha to dana.
	rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+dana.ID+"/roles", tenantA, adminTok,
		map[string]any{"role": "admin", "scope_type": "org", "scope_id": alpha})
	if rec.Code != http.StatusOK {
		t.Fatalf("delegate org alpha = %d: %s", rec.Code, rec.Body)
	}
	var granted directoryUser
	if err := json.Unmarshal(rec.Body.Bytes(), &granted); err != nil {
		t.Fatal(err)
	}
	want := store.ScopedRole{Role: "admin", ScopeType: "org", ScopeID: alpha, ScopeName: "Alpha"}
	if len(granted.Roles) != 0 || len(granted.ScopedRoles) != 1 || granted.ScopedRoles[0] != want {
		t.Fatalf("after the delegation dana = roles %v scoped %v, want no tenant role and %+v", granted.Roles, granted.ScopedRoles, want)
	}
	rec = bearerReq(t, h, http.MethodGet, "/v1/directory/users", tenantA, adminTok, nil)
	if !strings.Contains(rec.Body.String(), `"scope_name":"Alpha"`) {
		t.Fatalf("the directory listing does not show dana's delegation: %s", rec.Body)
	}

	// Dana administers Alpha and only Alpha, and holds nothing tenant-wide.
	tok, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(db.Pool()).Create(context.Background(), tenantA, dana.ID, "delegated", crypto.Hash([]byte(tok))); err != nil {
		t.Fatal(err)
	}
	rec = bearerReq(t, h, http.MethodGet, "/v1/hierarchy", tenantA, tok, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), alpha) || strings.Contains(rec.Body.String(), beta) {
		t.Fatalf("dana's hierarchy = %d, want Alpha and not Beta: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+alpha+"/teams", tenantA, tok, map[string]string{"slug": "platform", "name": "Platform"}); rec.Code != http.StatusCreated {
		t.Fatalf("dana creating a team in Alpha = %d, want 201: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+beta+"/teams", tenantA, tok, map[string]string{"slug": "sneak", "name": "Sneak"}); rec.Code != http.StatusForbidden {
		t.Fatalf("dana creating a team in Beta = %d, want 403: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodGet, "/v1/directory/users", tenantA, tok, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("dana reading the tenant directory = %d, want 403: %s", rec.Code, rec.Body)
	}

	// A delegated admin is not a tenant administrator: the last tenant-wide one
	// still cannot be removed.
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+owner.ID+"/roles/admin", tenantA, adminTok, nil); rec.Code != http.StatusConflict {
		t.Fatalf("removing the last tenant administrator while a delegated one exists = %d, want 409: %s", rec.Code, rec.Body)
	}

	// Tenant B cannot delegate tenant A's branch.
	carlos := created(adminBTok, tenantB, "deleg-carlos@example.com", "")
	if rec := bearerReq(t, h, http.MethodPost, "/v1/directory/users/"+carlos.ID+"/roles", tenantB, adminBTok,
		map[string]any{"role": "admin", "scope_type": "org", "scope_id": alpha}); rec.Code != http.StatusNotFound {
		t.Fatalf("tenant B delegating tenant A's org = %d, want 404: %s", rec.Code, rec.Body)
	}

	// Revoking the delegation ends it on dana's next request.
	if rec := bearerReq(t, h, http.MethodDelete, "/v1/directory/users/"+dana.ID+"/roles/admin?scope_type=org&scope_id="+alpha, tenantA, adminTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke the delegation = %d: %s", rec.Code, rec.Body)
	}
	if rec := bearerReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+alpha+"/teams", tenantA, tok, map[string]string{"slug": "late", "name": "Late"}); rec.Code != http.StatusForbidden {
		t.Fatalf("dana creating a team after the revoke = %d, want 403: %s", rec.Code, rec.Body)
	}
	var scoped int
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('directory.role_bind', 'directory.role_unbind')
		    AND data->>'scope_type' = 'org' AND data->>'scope_id' = $2`, tenantA, alpha).Scan(&scoped); err != nil {
		t.Fatal(err)
	}
	if scoped != 2 {
		t.Fatalf("audited delegation grant+revoke naming org Alpha = %d, want 2", scoped)
	}
}
