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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
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

func TestHierarchyResourceABACDenyTenantIsolationAndMutationBranches(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	tenantA := freshTenant(t, db, "hierarchy-abac-a")
	tenantB := freshTenant(t, db, "hierarchy-abac-b")

	createOrg := func(tenant, slug string) *store.Organization {
		t.Helper()
		var org *store.Organization
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(),
			func(ctx context.Context, scope tenancy.Scope) error {
				var err error
				org, err = (store.Organizations{}).Create(ctx, scope, slug, slug)
				return err
			}); err != nil {
			t.Fatal(err)
		}
		return org
	}
	deniedOrgA := createOrg(tenantA, "abac-denied")
	allowedOrgA := createOrg(tenantA, "abac-allowed")
	orgB := createOrg(tenantB, "abac-allowed")

	srv.abac = &abacCache{
		pool: db.Pool(),
		ttl:  time.Minute,
		data: map[string]abacEntry{
			tenantA: {
				policies: []auth.Policy{
					{
						Name:       "deny organization reads",
						Effect:     auth.PolicyDeny,
						Permission: permOrgRead,
						Resource: map[string]string{
							auth.ResourceTenantKey:         tenantA,
							string(auth.ScopeOrganization): deniedOrgA.ID,
						},
						Enabled: true,
					},
					{
						Name:       "deny organization writes",
						Effect:     auth.PolicyDeny,
						Permission: permOrgWrite,
						Resource: map[string]string{
							auth.ResourceTenantKey:         tenantA,
							string(auth.ScopeOrganization): deniedOrgA.ID,
						},
						Enabled: true,
					},
				},
				expiry: time.Now().Add(time.Minute),
			},
			tenantB: {
				policies: []auth.Policy{},
				expiry:   time.Now().Add(time.Minute),
			},
		},
		generations: map[string]uint64{},
	}

	principalA := auth.PrincipalWithPermissionGrants(
		&auth.Principal{TenantID: tenantA, UserID: "hierarchy-abac-user-a"},
		[]auth.PermissionGrant{
			{Permission: permOrgRead, ScopeType: auth.ScopeOrganization, ScopeID: deniedOrgA.ID},
			{Permission: permOrgWrite, ScopeType: auth.ScopeOrganization, ScopeID: deniedOrgA.ID},
			{Permission: permOrgRead, ScopeType: auth.ScopeOrganization, ScopeID: allowedOrgA.ID},
			{Permission: permOrgWrite, ScopeType: auth.ScopeOrganization, ScopeID: allowedOrgA.ID},
		},
	)
	principalB := &auth.Principal{
		TenantID: tenantB,
		UserID:   "hierarchy-abac-user-b",
		Permissions: map[string]bool{
			permOrgRead:  true,
			permOrgWrite: true,
		},
	}
	denied, err := srv.abacDenies(ctx, principalA, permOrgRead, map[string]string{
		auth.ResourceTenantKey:         tenantA,
		string(auth.ScopeOrganization): deniedOrgA.ID,
	})
	if err != nil || !denied {
		t.Fatalf("resource ABAC fixture denied=%v err=%v", denied, err)
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

	tenantAList := call(
		principalA, http.MethodGet, "/v1/hierarchy", "/v1/hierarchy",
		nil, srv.handleGetHierarchy, permOrgRead,
	)
	if tenantAList.Code != http.StatusOK {
		t.Fatalf("tenant A hierarchy = %d body=%s", tenantAList.Code, tenantAList.Body.String())
	}
	if strings.Contains(tenantAList.Body.String(), deniedOrgA.ID) {
		t.Fatalf("resource ABAC leaked denied organization: %s", tenantAList.Body.String())
	}
	if !strings.Contains(tenantAList.Body.String(), allowedOrgA.ID) {
		t.Fatalf("resource ABAC over-filtered allowed sibling: %s", tenantAList.Body.String())
	}
	if strings.Contains(tenantAList.Body.String(), orgB.ID) {
		t.Fatalf("tenant A hierarchy leaked tenant B organization: %s", tenantAList.Body.String())
	}

	tenantACreate := call(
		principalA,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+deniedOrgA.ID+"/teams",
		map[string]string{"slug": "denied", "name": "Denied"}, srv.handleCreateTeam, permOrgWrite,
	)
	if tenantACreate.Code != http.StatusForbidden {
		t.Fatalf("resource ABAC create = %d body=%s, want 403", tenantACreate.Code, tenantACreate.Body.String())
	}

	tenantAAllowedCreate := call(
		principalA,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+allowedOrgA.ID+"/teams",
		map[string]string{"slug": "allowed", "name": "Allowed"}, srv.handleCreateTeam, permOrgWrite,
	)
	if tenantAAllowedCreate.Code != http.StatusCreated {
		t.Fatalf("same-tenant allowed create = %d body=%s, want 201", tenantAAllowedCreate.Code, tenantAAllowedCreate.Body.String())
	}
	var allowedTeamA store.Team
	mustJSON(t, tenantAAllowedCreate, &allowedTeamA)
	tenantASiblingCreate := call(
		principalA,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+allowedOrgA.ID+"/teams",
		map[string]string{"slug": "allowed-sibling", "name": "Allowed sibling"}, srv.handleCreateTeam, permOrgWrite,
	)
	if tenantASiblingCreate.Code != http.StatusCreated {
		t.Fatalf("same-tenant sibling create = %d body=%s, want 201", tenantASiblingCreate.Code, tenantASiblingCreate.Body.String())
	}
	var allowedSiblingTeamA store.Team
	mustJSON(t, tenantASiblingCreate, &allowedSiblingTeamA)

	tenantBList := call(
		principalB, http.MethodGet, "/v1/hierarchy", "/v1/hierarchy",
		nil, srv.handleGetHierarchy, permOrgRead,
	)
	if tenantBList.Code != http.StatusOK || !strings.Contains(tenantBList.Body.String(), orgB.ID) {
		t.Fatalf("tenant B hierarchy = %d body=%s, want own organization", tenantBList.Code, tenantBList.Body.String())
	}
	if strings.Contains(tenantBList.Body.String(), deniedOrgA.ID) ||
		strings.Contains(tenantBList.Body.String(), allowedOrgA.ID) {
		t.Fatalf("tenant B hierarchy leaked tenant A organization: %s", tenantBList.Body.String())
	}

	tenantBCreate := call(
		principalB,
		http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", "/v1/hierarchy/orgs/"+orgB.ID+"/teams",
		map[string]string{"slug": "allowed", "name": "Allowed"}, srv.handleCreateTeam, permOrgWrite,
	)
	if tenantBCreate.Code != http.StatusCreated {
		t.Fatalf("tenant B create = %d body=%s, want 201", tenantBCreate.Code, tenantBCreate.Body.String())
	}
	var allowedTeamB store.Team
	mustJSON(t, tenantBCreate, &allowedTeamB)

	tenantWidePrincipal := func(tenant, user string) *auth.Principal {
		return &auth.Principal{
			TenantID: tenant,
			UserID:   user,
			Permissions: map[string]bool{
				permOrgWrite: true,
			},
		}
	}
	tenantWideA := tenantWidePrincipal(tenantA, "hierarchy-abac-root-a")
	tenantWideB := tenantWidePrincipal(tenantB, "hierarchy-abac-root-b")
	setTenantAPolicies := func(policies []auth.Policy) {
		srv.abac = &abacCache{
			pool: db.Pool(),
			ttl:  time.Minute,
			data: map[string]abacEntry{
				tenantA: {policies: policies, expiry: time.Now().Add(time.Minute)},
				tenantB: {policies: []auth.Policy{}, expiry: time.Now().Add(time.Minute)},
			},
			generations: map[string]uint64{},
		}
	}
	// Invoke the real handler adapter directly so each mutation proves the
	// handler's resolved-resource ABAC branch, rather than passing only because
	// the outer route middleware rejected a generic tenant resource first.
	callHandlerDirect := func(
		caller *auth.Principal,
		path, resourceID string,
		body any,
		handler apiHandler,
	) *httptest.ResponseRecorder {
		t.Helper()
		var requestBody bytes.Buffer
		if err := json.NewEncoder(&requestBody).Encode(body); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, &requestBody)
		req = req.WithContext(auth.WithPrincipal(req.Context(), caller))
		if resourceID != "" {
			req.SetPathValue("id", resourceID)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	organizationSlugs := func(tenant string) []string {
		t.Helper()
		var slugs []string
		if err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenant)),
			db.Pool(),
			func(ctx context.Context, scope tenancy.Scope) error {
				organizations, err := (store.Organizations{}).List(ctx, scope)
				if err != nil {
					return err
				}
				for _, organization := range organizations {
					slugs = append(slugs, organization.Slug)
				}
				return nil
			},
		); err != nil {
			t.Fatal(err)
		}
		return slugs
	}
	projectSlugs := func(tenant, teamID string) []string {
		t.Helper()
		var slugs []string
		if err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenant)),
			db.Pool(),
			func(ctx context.Context, scope tenancy.Scope) error {
				projects, err := (store.Projects{}).ListByTeam(ctx, scope, teamID)
				if err != nil {
					return err
				}
				for _, project := range projects {
					slugs = append(slugs, project.Slug)
				}
				return nil
			},
		); err != nil {
			t.Fatal(err)
		}
		return slugs
	}
	contains := func(values []string, target string) bool {
		for _, value := range values {
			if value == target {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "organization create",
			run: func(t *testing.T) {
				setTenantAPolicies([]auth.Policy{{
					Name:       "deny tenant organization writes",
					Effect:     auth.PolicyDeny,
					Permission: permOrgWrite,
					Resource:   map[string]string{auth.ResourceTenantKey: tenantA},
					Enabled:    true,
				}})
				const deniedSlug = "abac-denied-root"
				denied := callHandlerDirect(
					tenantWideA,
					"/v1/hierarchy/orgs",
					"",
					map[string]string{"slug": deniedSlug, "name": "Denied root"},
					srv.handleCreateOrganization,
				)
				if denied.Code != http.StatusForbidden {
					t.Fatalf("tenant A denied organization = %d body=%s, want 403", denied.Code, denied.Body.String())
				}
				if contains(organizationSlugs(tenantA), deniedSlug) {
					t.Fatal("tenant A denied organization was persisted")
				}

				for _, allowed := range []struct {
					principal *auth.Principal
					slug      string
				}{
					{principal: tenantWideB, slug: "abac-allowed-root-b"},
					{principal: tenantWideA, slug: "abac-allowed-root-a"},
				} {
					// Tenant B runs while tenant A's deny remains installed.
					// Clear it only for tenant A's same-tenant allowed control.
					if allowed.principal == tenantWideA {
						setTenantAPolicies(nil)
					}
					rec := callHandlerDirect(
						allowed.principal,
						"/v1/hierarchy/orgs",
						"",
						map[string]string{"slug": allowed.slug, "name": allowed.slug},
						srv.handleCreateOrganization,
					)
					if rec.Code != http.StatusCreated {
						t.Fatalf("allowed organization %s = %d body=%s, want 201", allowed.slug, rec.Code, rec.Body.String())
					}
				}
				slugsA, slugsB := organizationSlugs(tenantA), organizationSlugs(tenantB)
				if !contains(slugsA, "abac-allowed-root-a") ||
					contains(slugsA, "abac-allowed-root-b") ||
					!contains(slugsB, "abac-allowed-root-b") ||
					contains(slugsB, "abac-allowed-root-a") {
					t.Fatalf("allowed organizations are not tenant-isolated: tenantA=%v tenantB=%v", slugsA, slugsB)
				}
			},
		},
		{
			name: "project create",
			run: func(t *testing.T) {
				setTenantAPolicies([]auth.Policy{{
					Name:       "deny team project writes",
					Effect:     auth.PolicyDeny,
					Permission: permOrgWrite,
					Resource: map[string]string{
						auth.ResourceTenantKey: tenantA,
						string(auth.ScopeTeam): allowedTeamA.ID,
					},
					Enabled: true,
				}})
				const deniedSlug = "abac-denied-project"
				denied := callHandlerDirect(
					tenantWideA,
					"/v1/hierarchy/teams/"+allowedTeamA.ID+"/projects",
					allowedTeamA.ID,
					map[string]string{"slug": deniedSlug, "name": "Denied project"},
					srv.handleCreateProject,
				)
				if denied.Code != http.StatusForbidden {
					t.Fatalf("tenant A denied project = %d body=%s, want 403", denied.Code, denied.Body.String())
				}
				if contains(projectSlugs(tenantA, allowedTeamA.ID), deniedSlug) {
					t.Fatal("tenant A denied project was persisted")
				}

				for _, allowed := range []struct {
					principal *auth.Principal
					tenant    string
					teamID    string
					slug      string
				}{
					{principal: tenantWideA, tenant: tenantA, teamID: allowedSiblingTeamA.ID, slug: "abac-allowed-project-a"},
					{principal: tenantWideB, tenant: tenantB, teamID: allowedTeamB.ID, slug: "abac-allowed-project-b"},
				} {
					rec := callHandlerDirect(
						allowed.principal,
						"/v1/hierarchy/teams/"+allowed.teamID+"/projects",
						allowed.teamID,
						map[string]string{"slug": allowed.slug, "name": allowed.slug},
						srv.handleCreateProject,
					)
					if rec.Code != http.StatusCreated {
						t.Fatalf("allowed project %s = %d body=%s, want 201", allowed.slug, rec.Code, rec.Body.String())
					}
					if !contains(projectSlugs(allowed.tenant, allowed.teamID), allowed.slug) {
						t.Fatalf("allowed project %s was not persisted in tenant %s", allowed.slug, allowed.tenant)
					}
				}
				if contains(projectSlugs(tenantA, allowedTeamB.ID), "abac-allowed-project-b") ||
					contains(projectSlugs(tenantB, allowedSiblingTeamA.ID), "abac-allowed-project-a") {
					t.Fatal("allowed projects crossed the tenant storage boundary")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}
