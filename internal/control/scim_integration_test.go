// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// --- helpers ---

func scimToken(t *testing.T, db *store.DB, tenantID, name string) string {
	t.Helper()
	tok, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewScimTokens(db.Pool()).Create(context.Background(), tenantID, name, crypto.Hash([]byte(tok))); err != nil {
		t.Fatalf("mint scim token: %v", err)
	}
	return tok
}

func scimReq(t *testing.T, h http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *bytes.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	} else {
		r = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/scim+json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func scimUserBody(userName, ext, dept string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName +
		`","externalId":"` + ext + `","name":{"formatted":"Test User"},"emails":[{"value":"` + userName +
		`","primary":true}],"active":true,"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"` + dept + `"}}`
}

func scimID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	mustJSON(t, rec, &m)
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatalf("no id in SCIM response: %s", rec.Body)
	}
	return id
}

func sessionReq(t *testing.T, h http.Handler, method, path string, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *bytes.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	} else {
		r = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- SCIM Users lifecycle + conformance ---

func TestSCIMUserLifecycleAndConformance(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "scim")
	token := scimToken(t, db, tenant, "okta")

	rec := scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("ada@x.com", "ext-1", "netops"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("content-type = %q, want application/scim+json", ct)
	}
	id := scimID(t, rec)
	var created map[string]any
	mustJSON(t, rec, &created)
	if created["active"] != true || created["externalId"] != "ext-1" {
		t.Errorf("created user = %+v", created)
	}

	// duplicate userName → 409 uniqueness
	if dup := scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("ada@x.com", "ext-2", "netops")); dup.Code != http.StatusConflict {
		t.Errorf("duplicate userName: %d %s, want 409", dup.Code, dup.Body)
	}

	// list filter (URL-encoded `userName eq "ada@x.com"`)
	q := url.Values{"filter": {`userName eq "ada@x.com"`}}.Encode()
	list := scimReq(t, h, http.MethodGet, "/scim/v2/Users?"+q, token, "")
	var lr map[string]any
	mustJSON(t, list, &lr)
	if list.Code != http.StatusOK || lr["totalResults"].(float64) != 1 {
		t.Errorf("list filter: %d %+v", list.Code, lr)
	}

	// get
	if g := scimReq(t, h, http.MethodGet, "/scim/v2/Users/"+id, token, ""); g.Code != http.StatusOK {
		t.Errorf("get: %d %s", g.Code, g.Body)
	}

	// deactivate via PATCH (Okta valueless form)
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`
	pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, patch)
	var patched map[string]any
	mustJSON(t, pr, &patched)
	if pr.Code != http.StatusOK || patched["active"] != false {
		t.Errorf("patch deactivate: %d active=%v", pr.Code, patched["active"])
	}

	// delete → 204, then gone (404)
	if d := scimReq(t, h, http.MethodDelete, "/scim/v2/Users/"+id, token, ""); d.Code != http.StatusNoContent {
		t.Errorf("delete: %d", d.Code)
	}
	if g := scimReq(t, h, http.MethodGet, "/scim/v2/Users/"+id, token, ""); g.Code != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", g.Code)
	}
}

// --- bearer auth + tenant isolation ---

func TestSCIMAuthAndTenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	tA := freshTenant(t, db, "scimA")
	tokA := scimToken(t, db, tA, "a")
	tB := freshTenant(t, db, "scimB")
	tokB := scimToken(t, db, tB, "b")

	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no bearer: %d, want 401", rec.Code)
	}
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users", "bogus-token", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid bearer: %d, want 401", rec.Code)
	}

	// create a user in A
	id := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", tokA, scimUserBody("only-a@x.com", "a-1", "x")))
	// B's token cannot see A's user (RLS) → 404
	if rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users/"+id, tokB, ""); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant get: %d, want 404", rec.Code)
	}
}

// --- deprovision → IMMEDIATE session revocation (the S31 Done-when) ---

func TestSCIMDeprovisionRevokesSession(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "scimdep")
	token := scimToken(t, db, tenant, "okta")

	id := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("bob@x.com", "dep-1", "x")))

	// mint a live session for the user
	sessTok, err := srv.sessions.Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: id, Email: "bob@x.com", DisplayName: "Bob", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: auth.SessionCookie, Value: sessTok}

	if rec := withCookie(t, h, http.MethodGet, "/v1/me", cookie); rec.Code != http.StatusOK {
		t.Fatalf("session should resolve before deprovision: %d %s", rec.Code, rec.Body)
	}

	// deprovision via SCIM (active=false)
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	if pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, patch); pr.Code != http.StatusOK {
		t.Fatalf("deprovision: %d %s", pr.Code, pr.Body)
	}

	// the session is revoked at once → 401
	if rec := withCookie(t, h, http.MethodGet, "/v1/me", cookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("session must be revoked immediately on deprovision: %d", rec.Code)
	}
}

// --- SCIM Groups → role + membership (group-sync mapping) ---

func TestSCIMGroupsMembership(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "scimgrp")
	token := scimToken(t, db, tenant, "okta")

	uid := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("eng@x.com", "g-1", "eng")))

	gBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineers","members":[{"value":"` + uid + `"}]}`
	grec := scimReq(t, h, http.MethodPost, "/scim/v2/Groups", token, gBody)
	if grec.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", grec.Code, grec.Body)
	}
	gid := scimID(t, grec)

	if g := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+gid, token, ""); !strings.Contains(g.Body.String(), uid) {
		t.Errorf("group should list the member: %s", g.Body)
	}

	// remove the member (filter form)
	rm := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[value eq \"` + uid + `\"]"}]}`
	if pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, rm); pr.Code != http.StatusOK {
		t.Fatalf("patch remove member: %d %s", pr.Code, pr.Body)
	}
	if g := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+gid, token, ""); strings.Contains(g.Body.String(), uid) {
		t.Errorf("member should be removed: %s", g.Body)
	}
}

// --- ABAC enforced over RBAC ---

// createUserWithPerm provisions a user (with attributes) and grants it a single
// permission via a fresh role bound at tenant scope.
func createUserWithPerm(t *testing.T, db *store.DB, tenant, email string, attrs map[string]string, perm string) string {
	t.Helper()
	var uid string
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, e := store.Users{}.CreateSCIM(ctx, sc, store.User{Email: email, UserName: email, Attributes: attrs})
		if e != nil {
			return e
		}
		uid = u.ID
		role, e := store.Roles{}.Create(ctx, sc, "svc-"+email[:3], "svc", "")
		if e != nil {
			return e
		}
		if e := (store.Roles{}).AddPermission(ctx, sc, role.ID, perm); e != nil {
			return e
		}
		return store.RoleBindings{}.Bind(ctx, sc, "user", uid, role.ID)
	})
	if err != nil {
		t.Fatalf("create user with perm: %v", err)
	}
	return uid
}

func createDenyPolicy(t *testing.T, db *store.DB, tenant, perm string, subj map[string]string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := store.ABACPolicies{}.Create(ctx, sc, auth.Policy{
			Name: "deny-" + perm, Effect: auth.PolicyDeny, Permission: perm, Subject: subj, Priority: 10, Enabled: true,
		})
		return e
	})
	if err != nil {
		t.Fatalf("create deny policy: %v", err)
	}
}

func TestABACEnforcedOverRBAC(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	testBody := `{"name":"t","type":"icmp","target":"1.1.1.1"}`

	// Tenant 1: a contractor with test.write (RBAC) but a DENY policy → 403.
	t1 := freshTenant(t, db, "abac1")
	u1 := createUserWithPerm(t, db, t1, "con@x.com", map[string]string{"department": "contractor"}, "test.write")
	createDenyPolicy(t, db, t1, "test.write", map[string]string{"department": "contractor"})
	sess1, err := srv.sessions.Issue(context.Background(), auth.Session{TenantID: t1, UserID: u1, Email: "con@x.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	rec := sessionReq(t, h, http.MethodPost, "/v1/tests", &http.Cookie{Name: auth.SessionCookie, Value: sess1}, testBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ABAC should deny the RBAC-permitted write: %d %s", rec.Code, rec.Body)
	}

	// Tenant 2: same RBAC grant, no policy → allowed (201).
	t2 := freshTenant(t, db, "abac2")
	u2 := createUserWithPerm(t, db, t2, "stf@x.com", map[string]string{"department": "netops"}, "test.write")
	sess2, err := srv.sessions.Issue(context.Background(), auth.Session{TenantID: t2, UserID: u2, Email: "stf@x.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	rec = sessionReq(t, h, http.MethodPost, "/v1/tests", &http.Cookie{Name: auth.SessionCookie, Value: sess2}, testBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("RBAC-permitted write with no policy should succeed: %d %s", rec.Code, rec.Body)
	}
}

// --- SCIM Group PATCH: rename applies, and a failed sync is atomic + honest ---

// Regression for two silent-failure bugs in scimPatchGroup: (1) a PATCH that
// replaced displayName parsed the rename and then dropped it on the floor
// (the handler never applied gp.DisplayName); (2) every Bind/Unbind error was
// discarded (`_ =`), so a half-failed membership sync answered 200 OK and the
// IdP believed state that didn't exist.
func TestSCIMGroupRenameAndAtomicPatch(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "scimren")
	token := scimToken(t, db, tenant, "okta")

	uid := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("ren@x.com", "g-ren-1", "eng")))
	gBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineers","members":[{"value":"` + uid + `"}]}`
	grec := scimReq(t, h, http.MethodPost, "/scim/v2/Groups", token, gBody)
	if grec.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", grec.Code, grec.Body)
	}
	gid := scimID(t, grec)

	// 1. Rename via PATCH replace displayName — silently dropped before the fix.
	ren := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Platform Engineers"}]}`
	pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, ren)
	if pr.Code != http.StatusOK {
		t.Fatalf("patch rename: %d %s", pr.Code, pr.Body)
	}
	if !strings.Contains(pr.Body.String(), "Platform Engineers") {
		t.Errorf("rename not applied in the PATCH response: %s", pr.Body)
	}
	g := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+gid, token, "")
	if !strings.Contains(g.Body.String(), "Platform Engineers") {
		t.Errorf("rename not persisted: %s", g.Body)
	}
	if !strings.Contains(g.Body.String(), uid) {
		t.Errorf("membership must survive a rename: %s", g.Body)
	}

	// An empty displayName is rejected up front, applying nothing.
	empty := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":""}]}`
	if er := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, empty); er.Code != http.StatusBadRequest {
		t.Errorf("empty displayName = %d, want 400", er.Code)
	}

	// 2. Atomicity: one PATCH adding a valid member AND a malformed member id
	// must fail as a WHOLE — a real error (not 200, and not the old lying
	// 404) — and apply NOTHING from the request.
	u2 := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("ren2@x.com", "g-ren-2", "eng")))
	bad := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[` +
		`{"op":"add","path":"members","value":[{"value":"` + u2 + `"}]},` +
		`{"op":"add","path":"members","value":[{"value":"not-a-uuid"}]}]}`
	br := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, bad)
	if br.Code == http.StatusOK {
		t.Fatalf("a failed sync must not answer 200: %s", br.Body)
	}
	if br.Code == http.StatusNotFound {
		t.Fatalf("a write failure must not masquerade as 404: %s", br.Body)
	}
	after := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+gid, token, "")
	if strings.Contains(after.Body.String(), u2) {
		t.Errorf("atomicity: the valid member from the failed PATCH must be rolled back: %s", after.Body)
	}
	if !strings.Contains(after.Body.String(), uid) {
		t.Errorf("pre-existing membership must be untouched by the failed PATCH: %s", after.Body)
	}
}
