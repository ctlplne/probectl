// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"testing"
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
