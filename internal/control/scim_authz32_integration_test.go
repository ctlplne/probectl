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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// grantPermToUser binds an existing user to a fresh role carrying one permission.
func grantPermToUser(t *testing.T, db *store.DB, tenant, userID, perm string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		role, e := store.Roles{}.Create(ctx, sc, "svc-"+userID[:8], "svc", "")
		if e != nil {
			return e
		}
		if e := (store.Roles{}).AddPermission(ctx, sc, role.ID, perm); e != nil {
			return e
		}
		return store.RoleBindings{}.Bind(ctx, sc, "user", userID, role.ID)
	})
	if err != nil {
		t.Fatalf("grant perm to user: %v", err)
	}
}

// TestSCIMDepartmentPatchFlipsABACDecisionAUTHZ32 is the headline AUTHZ-32
// regression, end to end through the real SCIM + /v1 HTTP surfaces: an Entra
// enterprise-extension department PATCH must PERSIST into users.attributes, and
// the very next authenticated request must re-read it so an ABAC deny policy on
// department=contractor begins denying a write that previously succeeded.
//
// Baseline (72e7a2b): the department PATCH answers 200 but ApplyUserPatch drops
// the path, so attributes never change and the second write still succeeds —
// the test is RED at the "ABAC should now deny" assertion.
func TestSCIMDepartmentPatchFlipsABACDecisionAUTHZ32(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "authz32dept")
	token := scimToken(t, db, tenant, "entra")
	testBody := `{"name":"t","type":"icmp","target":"1.1.1.1"}`

	// Provision a contractor-eligible user starting in department=netops.
	id := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("flip@x.com", "flip-1", "netops")))
	grantPermToUser(t, db, tenant, id, "test.write")
	createDenyPolicy(t, db, tenant, "test.write", map[string]string{"department": "contractor"})

	sess, err := srv.sessions.Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: id, Email: "flip@x.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: auth.SessionCookie, Value: sess}

	// department=netops: the deny policy does not match → write allowed.
	rec := sessionReq(t, h, http.MethodPost, "/v1/tests", cookie, testBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("pre-PATCH write (department=netops) = %d %s, want 201", rec.Code, rec.Body)
	}
	if rotated := findCookie(rec.Result().Cookies(), auth.SessionCookie); rotated != nil && rotated.Value != "" {
		cookie = rotated
	}

	// Entra department PATCH → contractor.
	const deptPath = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"` + deptPath + `","value":"contractor"}]}`
	pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, patch)
	if pr.Code != http.StatusOK {
		t.Fatalf("department PATCH = %d %s, want 200", pr.Code, pr.Body)
	}
	if !strings.Contains(pr.Body.String(), "contractor") {
		t.Fatalf("department PATCH response did not reflect the change: %s", pr.Body)
	}

	// GET must show the persisted department (proves the write hit the store).
	got := scimReq(t, h, http.MethodGet, "/scim/v2/Users/"+id, token, "")
	if !strings.Contains(got.Body.String(), `"department":"contractor"`) {
		t.Fatalf("department not persisted to the store: %s", got.Body)
	}

	// department=contractor: the deny policy now matches on the NEXT request.
	rec = sessionReq(t, h, http.MethodPost, "/v1/tests", cookie, testBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("post-PATCH write (department=contractor) = %d %s, want 403 (ABAC deny must flip)", rec.Code, rec.Body)
	}
}

// TestSCIMUserFilterFailsClosedHTTPAUTHZ32 proves the Users-list filter no longer
// fails open: an unsupported filter is 400 invalidFilter (not a tenant-wide
// list), and `externalId eq` selects exactly the matching user.
//
// Baseline: scimEqFilter only understood userName, returned "" for every other
// filter, and the handler treated "" as "no filter" — so the externalId query
// returned ALL users. RED at totalResults==1 and at the 400 assertion.
func TestSCIMUserFilterFailsClosedHTTPAUTHZ32(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "authz32filter")
	token := scimToken(t, db, tenant, "okta")

	aa := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("aa@x.com", "ext-aa", "eng")))
	_ = scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("bb@x.com", "ext-bb", "eng")))

	// externalId eq → exactly one user (the fail-open bug returned both).
	q := url.Values{"filter": {`externalId eq "ext-aa"`}}.Encode()
	ext := scimList(t, scimReq(t, h, http.MethodGet, "/scim/v2/Users?"+q, token, ""))
	if ext.TotalResults != 1 || len(ext.Resources) != 1 || ext.Resources[0]["id"] != aa {
		t.Fatalf("externalId filter = %+v, want exactly aa (%s)", ext, aa)
	}

	// userName eq still works.
	q = url.Values{"filter": {`userName eq "bb@x.com"`}}.Encode()
	un := scimList(t, scimReq(t, h, http.MethodGet, "/scim/v2/Users?"+q, token, ""))
	if un.TotalResults != 1 {
		t.Fatalf("userName filter = %+v, want 1", un)
	}

	// unsupported filters → 400 invalidFilter, NOT a list.
	for _, bad := range []string{`userName sw "a"`, `emails.value co "x"`, `userName eq "a" or userName eq "b"`} {
		q = url.Values{"filter": {bad}}.Encode()
		rec := scimReq(t, h, http.MethodGet, "/scim/v2/Users?"+q, token, "")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalidFilter"`) {
			t.Fatalf("unsupported filter %q = %d %s, want 400 invalidFilter", bad, rec.Code, rec.Body)
		}
	}

	// empty filter still lists everyone in the tenant.
	all := scimList(t, scimReq(t, h, http.MethodGet, "/scim/v2/Users?count=50", token, ""))
	if all.TotalResults != 2 {
		t.Fatalf("empty filter = %+v, want all 2 users", all)
	}
}

// TestSCIMEmailsValuePatchPersistsAUTHZ32: an `emails[type eq "work"].value`
// replace changes the user's address (it fell through silently on the baseline).
func TestSCIMEmailsValuePatchPersistsAUTHZ32(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "authz32email")
	token := scimToken(t, db, tenant, "entra")

	id := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("mail@x.com", "mail-1", "eng")))
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"mail-work@x.com"}]}`
	pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, patch)
	if pr.Code != http.StatusOK {
		t.Fatalf("emails PATCH = %d %s, want 200", pr.Code, pr.Body)
	}
	got := scimReq(t, h, http.MethodGet, "/scim/v2/Users/"+id, token, "")
	if !strings.Contains(got.Body.String(), "mail-work@x.com") {
		t.Fatalf("emails value not persisted: %s", got.Body)
	}
}

// TestSCIMUnsupportedUserPatchPathFailsClosedAUTHZ32: a path the server does not
// implement is 400 invalidPath (baseline answered 200 and ignored it).
func TestSCIMUnsupportedUserPatchPathFailsClosedAUTHZ32(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "authz32path")
	token := scimToken(t, db, tenant, "okta")

	id := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("path@x.com", "path-1", "eng")))
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"boss"}]}`
	rec := scimReq(t, h, http.MethodPatch, "/scim/v2/Users/"+id, token, patch)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalidPath"`) {
		t.Fatalf("unsupported PATCH path = %d %s, want 400 invalidPath", rec.Code, rec.Body)
	}
}

// TestSCIMGroupRemoveAllMembersAUTHZ32: a valueless `remove` on members unbinds
// EVERY member (RFC 7644). The baseline parsed it to an empty remove set and
// answered 200 while the members stayed bound — RED at "0 members remain".
func TestSCIMGroupRemoveAllMembersAUTHZ32(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "authz32rmall")
	token := scimToken(t, db, tenant, "okta")

	u1 := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("m1@x.com", "m1", "eng")))
	u2 := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Users", token, scimUserBody("m2@x.com", "m2", "eng")))

	gBody := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"All Hands","members":[{"value":"` + u1 + `"},{"value":"` + u2 + `"}]}`
	gid := scimID(t, scimReq(t, h, http.MethodPost, "/scim/v2/Groups", token, gBody))

	rm := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`
	if pr := scimReq(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, rm); pr.Code != http.StatusOK {
		t.Fatalf("remove-all members PATCH = %d %s, want 200", pr.Code, pr.Body)
	}
	after := scimReq(t, h, http.MethodGet, "/scim/v2/Groups/"+gid, token, "")
	if strings.Contains(after.Body.String(), u1) || strings.Contains(after.Body.String(), u2) {
		t.Fatalf("valueless members remove must unbind ALL members: %s", after.Body)
	}
}
