// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

func TestHierarchyRoutesRequireOrgPermissions(t *testing.T) {
	want := map[string]string{
		"GET /v1/hierarchy":                      permOrgRead,
		"POST /v1/hierarchy/orgs":                permOrgWrite,
		"POST /v1/hierarchy/orgs/{id}/teams":     permOrgWrite,
		"POST /v1/hierarchy/teams/{id}/projects": permOrgWrite,
	}
	seen := map[string]bool{}
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		key := rt.Method + " " + rt.Pattern
		perm, ok := want[key]
		if !ok {
			continue
		}
		seen[key] = true
		if rt.Permission != perm {
			t.Fatalf("%s permission = %q, want %q", key, rt.Permission, perm)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Fatalf("route %s not registered", key)
		}
	}
}

func TestHierarchyNoPoolFailsUnavailable(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/hierarchy")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /v1/hierarchy without pool = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScopedRBACHierarchyRoutesAdmitOnlyForLineageCheck(t *testing.T) {
	srv := testServer(fakePinger{})
	principal := auth.PrincipalWithPermissionGrants(&auth.Principal{
		TenantID: "00000000-0000-0000-0000-000000000001",
		UserID:   "user-a",
	}, []auth.PermissionGrant{{
		Permission: permOrgWrite,
		ScopeType:  auth.ScopeOrganization,
		ScopeID:    "org-a",
	}})
	req := httptest.NewRequest(http.MethodPost, "/v1/hierarchy/orgs/org-a/teams", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	called := false
	handler := func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	}

	if err := srv.requireAnyPermission(permOrgWrite, handler)(httptest.NewRecorder(), req); err != nil {
		t.Fatalf("scoped hierarchy route edge rejected grant before lineage lookup: %v", err)
	}
	if !called {
		t.Fatal("scope-aware route did not reach lineage-checking handler")
	}
	called = false
	err := srv.requirePermission(permOrgWrite, handler)(httptest.NewRecorder(), req)
	if errKind(t, err) != apierror.KindForbidden || called {
		t.Fatalf("ordinary tenant-wide route accepted scoped grant: err=%v called=%v", err, called)
	}

	for _, tc := range []struct {
		method, pattern string
		want            bool
	}{
		{http.MethodGet, "/v1/hierarchy", true},
		{http.MethodPost, "/v1/hierarchy/orgs", false},
		{http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", true},
		{http.MethodPost, "/v1/hierarchy/teams/{id}/projects", true},
	} {
		if got := hierarchyRouteAcceptsScopedGrant(tc.method, tc.pattern); got != tc.want {
			t.Errorf("%s %s scope-aware = %v, want %v", tc.method, tc.pattern, got, tc.want)
		}
	}
}
