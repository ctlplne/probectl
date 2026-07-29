// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestHierarchyAPITenantScopedTree(t *testing.T) {
	h, db := setupAPI(t)
	suffix := time.Now().UnixNano()

	orgRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs", "", map[string]any{
		"slug": fmt.Sprintf("eng-%d", suffix), "name": "Engineering",
	})
	if orgRec.Code != http.StatusCreated {
		t.Fatalf("create org = %d body=%s", orgRec.Code, orgRec.Body.String())
	}
	var org store.Organization
	mustJSON(t, orgRec, &org)

	teamRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+org.ID+"/teams", "", map[string]any{
		"slug": "platform", "name": "Platform",
	})
	if teamRec.Code != http.StatusCreated {
		t.Fatalf("create team = %d body=%s", teamRec.Code, teamRec.Body.String())
	}
	var team store.Team
	mustJSON(t, teamRec, &team)

	projectRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/teams/"+team.ID+"/projects", "", map[string]any{
		"slug": "edge", "name": "Edge Observability",
	})
	if projectRec.Code != http.StatusCreated {
		t.Fatalf("create project = %d body=%s", projectRec.Code, projectRec.Body.String())
	}

	list := apiReq(t, h, http.MethodGet, "/v1/hierarchy", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list hierarchy = %d body=%s", list.Code, list.Body.String())
	}
	var tree hierarchyResponse
	mustJSON(t, list, &tree)
	if !hierarchyContains(tree, org.ID, team.ID, "edge") {
		t.Fatalf("hierarchy missing created org/team/project: %+v", tree)
	}

	tenantB := freshTenant(t, db, "hier")
	orgBRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs", tenantB, map[string]any{
		"slug": fmt.Sprintf("tenant-b-%d", suffix), "name": "Tenant B",
	})
	if orgBRec.Code != http.StatusCreated {
		t.Fatalf("create tenant B org = %d body=%s", orgBRec.Code, orgBRec.Body.String())
	}
	var orgB store.Organization
	mustJSON(t, orgBRec, &orgB)

	cross := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+orgB.ID+"/teams", "", map[string]any{
		"slug": "sneaky", "name": "Sneaky",
	})
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant parent create = %d body=%s", cross.Code, cross.Body.String())
	}

	defaultList := apiReq(t, h, http.MethodGet, "/v1/hierarchy", "", nil)
	if strings.Contains(defaultList.Body.String(), orgB.ID) || strings.Contains(defaultList.Body.String(), "Tenant B") {
		t.Fatalf("default tenant saw tenant B hierarchy: %s", defaultList.Body.String())
	}
	tenantBList := apiReq(t, h, http.MethodGet, "/v1/hierarchy", tenantB, nil)
	if !strings.Contains(tenantBList.Body.String(), orgB.ID) || strings.Contains(tenantBList.Body.String(), org.ID) {
		t.Fatalf("tenant B hierarchy not isolated: %s", tenantBList.Body.String())
	}
}

func hierarchyContains(tree hierarchyResponse, orgID, teamID, projectSlug string) bool {
	for _, org := range tree.Items {
		if org.ID != orgID {
			continue
		}
		for _, team := range org.Teams {
			if team.ID != teamID {
				continue
			}
			for _, project := range team.Projects {
				if project.Slug == projectSlug {
					return true
				}
			}
		}
	}
	return false
}

func TestScopedRBACHierarchySiblingAndTenantIsolation(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	tenantA := freshTenant(t, db, "scoped-hierarchy-a")
	tenantB := freshTenant(t, db, "scoped-hierarchy-b")

	var userID string
	var alpha, beta, foreign *store.Organization
	var alphaSiblingTeam, foreignTeam *store.Team
	seedA := func(ctx context.Context, scope tenancy.Scope) error {
		var err error
		alpha, err = (store.Organizations{}).Create(ctx, scope, "alpha", "Alpha")
		if err != nil {
			return err
		}
		beta, err = (store.Organizations{}).Create(ctx, scope, "beta", "Beta sibling secret")
		if err != nil {
			return err
		}
		alphaSiblingTeam, err = (store.Teams{}).Create(ctx, scope, alpha.ID, "alpha-sibling", "Alpha sibling team secret")
		if err != nil {
			return err
		}
		user, err := (store.Users{}).Create(ctx, scope, fmt.Sprintf("delegated-%d@example.test", suffix), "Delegated editor")
		if err != nil {
			return err
		}
		userID = user.ID
		role, err := (store.Roles{}).Create(ctx, scope, "delegated-org-editor", "Delegated org editor", "")
		if err != nil {
			return err
		}
		for _, permission := range []string{permOrgRead, permOrgWrite} {
			if err := (store.Roles{}).AddPermission(ctx, scope, role.ID, permission); err != nil {
				return err
			}
		}
		_, err = (store.RoleBindings{}).Create(ctx, scope, "user", user.ID, role.ID, "org", &alpha.ID)
		return err
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA)), db.Pool(), seedA); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantB)), db.Pool(),
		func(ctx context.Context, scope tenancy.Scope) error {
			var err error
			foreign, err = (store.Organizations{}).Create(ctx, scope, "alpha", "Tenant B alpha secret")
			if err != nil {
				return err
			}
			foreignTeam, err = (store.Teams{}).Create(ctx, scope, foreign.ID, "foreign-team", "Foreign team secret")
			return err
		}); err != nil {
		t.Fatal(err)
	}

	grants, err := (permLoader{pool: db.Pool()}).ForUser(ctx, tenantA, userID)
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.PrincipalWithPermissionGrants(
		&auth.Principal{TenantID: tenantA, UserID: userID, Email: "delegated@example.test"},
		grants,
	)
	if principal.Has(permOrgWrite) || !principal.HasAny(permOrgWrite) {
		t.Fatalf("scoped grant was flattened or lost: %+v", principal)
	}

	call := func(caller *auth.Principal, method, pattern, path string, body any, handler apiHandler, permission string) *httptest.ResponseRecorder {
		t.Helper()
		var requestBody bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&requestBody).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, &requestBody)
		req = req.WithContext(auth.WithPrincipal(req.Context(), caller))
		if strings.Contains(pattern, "/orgs/{id}/") {
			req.SetPathValue("id", strings.Split(path, "/")[4])
		}
		if strings.Contains(pattern, "/teams/{id}/") {
			req.SetPathValue("id", strings.Split(path, "/")[4])
		}
		protected := srv.requirePermission(permission, handler)
		if hierarchyRouteAcceptsScopedGrant(method, pattern) {
			protected = srv.requireAnyPermission(permission, handler)
		}
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec
	}

	alphaCreate := call(
		principal,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+alpha.ID+"/teams",
		map[string]string{"slug": "allowed", "name": "Allowed"}, srv.handleCreateTeam, permOrgWrite,
	)
	if alphaCreate.Code != http.StatusCreated {
		t.Fatalf("matching org create = %d body=%s", alphaCreate.Code, alphaCreate.Body.String())
	}
	var allowedTeam store.Team
	mustJSON(t, alphaCreate, &allowedTeam)

	siblingCreate := call(
		principal,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+beta.ID+"/teams",
		map[string]string{"slug": "denied", "name": "Denied"}, srv.handleCreateTeam, permOrgWrite,
	)
	if siblingCreate.Code != http.StatusForbidden {
		t.Fatalf("sibling org create = %d body=%s, want 403", siblingCreate.Code, siblingCreate.Body.String())
	}

	foreignCreate := call(
		principal,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+foreign.ID+"/teams",
		map[string]string{"slug": "invisible", "name": "Invisible"}, srv.handleCreateTeam, permOrgWrite,
	)
	if foreignCreate.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant parent = %d body=%s, want tenant-first 404", foreignCreate.Code, foreignCreate.Body.String())
	}

	teamPrincipal := auth.PrincipalWithPermissionGrants(
		&auth.Principal{TenantID: tenantA, UserID: userID},
		[]auth.PermissionGrant{{Permission: permOrgWrite, ScopeType: auth.ScopeTeam, ScopeID: allowedTeam.ID}},
	)
	projectCreate := call(
		teamPrincipal,
		http.MethodPost, "/v1/hierarchy/teams/{id}/projects", "/v1/hierarchy/teams/"+allowedTeam.ID+"/projects",
		map[string]string{"slug": "target-project", "name": "Target project"}, srv.handleCreateProject, permOrgWrite,
	)
	if projectCreate.Code != http.StatusCreated {
		t.Fatalf("matching team project create = %d body=%s", projectCreate.Code, projectCreate.Body.String())
	}
	var targetProject store.Project
	mustJSON(t, projectCreate, &targetProject)

	siblingTeamCreate := call(
		teamPrincipal,
		http.MethodPost, "/v1/hierarchy/teams/{id}/projects", "/v1/hierarchy/teams/"+alphaSiblingTeam.ID+"/projects",
		map[string]string{"slug": "denied-project", "name": "Denied project"}, srv.handleCreateProject, permOrgWrite,
	)
	if siblingTeamCreate.Code != http.StatusForbidden {
		t.Fatalf("sibling team project create = %d body=%s, want 403", siblingTeamCreate.Code, siblingTeamCreate.Body.String())
	}
	foreignTeamCreate := call(
		teamPrincipal,
		http.MethodPost, "/v1/hierarchy/teams/{id}/projects", "/v1/hierarchy/teams/"+foreignTeam.ID+"/projects",
		map[string]string{"slug": "foreign-project", "name": "Foreign project"}, srv.handleCreateProject, permOrgWrite,
	)
	if foreignTeamCreate.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant team = %d body=%s, want tenant-first 404", foreignTeamCreate.Code, foreignTeamCreate.Body.String())
	}

	var siblingProject *store.Project
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA)), db.Pool(),
		func(ctx context.Context, scope tenancy.Scope) error {
			var err error
			siblingProject, err = (store.Projects{}).Create(ctx, scope, allowedTeam.ID, "sibling-project", "Sibling project secret")
			return err
		}); err != nil {
		t.Fatal(err)
	}
	projectPrincipal := auth.PrincipalWithPermissionGrants(
		&auth.Principal{TenantID: tenantA, UserID: userID},
		[]auth.PermissionGrant{{Permission: permOrgRead, ScopeType: auth.ScopeProject, ScopeID: targetProject.ID}},
	)
	list := call(projectPrincipal, http.MethodGet, "/v1/hierarchy", "/v1/hierarchy", nil, srv.handleGetHierarchy, permOrgRead)
	if list.Code != http.StatusOK {
		t.Fatalf("scoped hierarchy list = %d body=%s", list.Code, list.Body.String())
	}
	body := list.Body.String()
	if !strings.Contains(body, alpha.ID) || !strings.Contains(body, allowedTeam.ID) || !strings.Contains(body, targetProject.ID) {
		t.Fatalf("matching hierarchy missing: %s", body)
	}
	for _, secret := range []string{
		alphaSiblingTeam.ID, "Alpha sibling team secret",
		siblingProject.ID, "Sibling project secret",
		beta.ID, "Beta sibling secret",
		foreign.ID, "Tenant B alpha secret",
		foreignTeam.ID, "Foreign team secret",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("scoped hierarchy leaked %q: %s", secret, body)
		}
	}

	// A scoped grant cannot create a new top-level organization because there
	// is no pre-existing resource lineage to delegate from.
	rootCreate := call(
		principal,
		http.MethodPost, "/v1/hierarchy/orgs", "/v1/hierarchy/orgs",
		map[string]string{"slug": "promoted", "name": "Promoted"}, srv.handleCreateOrganization, permOrgWrite,
	)
	if rootCreate.Code != http.StatusForbidden {
		t.Fatalf("scoped grant created top-level org: %d body=%s", rootCreate.Code, rootCreate.Body.String())
	}
}
