// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type hierarchyResponse struct {
	Items []hierarchyOrganization `json:"items"`
}

type hierarchyOrganization struct {
	store.Organization
	Teams []hierarchyTeam `json:"teams"`
}

type hierarchyTeam struct {
	store.Team
	Projects []store.Project `json:"projects"`
}

type hierarchyCreateRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func hierarchyRouteAcceptsScopedGrant(method, pattern string) bool {
	switch method + " " + pattern {
	case "GET /v1/hierarchy",
		"POST /v1/hierarchy/orgs/{id}/teams",
		"POST /v1/hierarchy/teams/{id}/projects":
		return true
	default:
		return false
	}
}

// handleGetHierarchy serves the caller tenant's org/team/project tree. Every
// read goes through tenancy.InTenant, so Postgres RLS is the outer boundary.
func (s *Server) handleGetHierarchy(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("hierarchy store is not configured")
	}
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil || !principal.HasAny(permOrgRead) {
		return apierror.Forbidden("missing permission: " + permOrgRead)
	}
	var resp hierarchyResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		tree, err := s.loadHierarchy(ctx, sc, principal)
		resp.Items = tree
		return err
	}); err != nil {
		return err
	}
	if resp.Items == nil {
		resp.Items = []hierarchyOrganization{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func hierarchyResource(principal *auth.Principal, lineage auth.ResourceLineage) map[string]string {
	resource := map[string]string{
		auth.ResourceTenantKey: principal.TenantID,
	}
	if lineage.OrganizationID != "" {
		resource[string(auth.ScopeOrganization)] = lineage.OrganizationID
	}
	if lineage.TeamID != "" {
		resource[string(auth.ScopeTeam)] = lineage.TeamID
	}
	if lineage.ProjectID != "" {
		resource[string(auth.ScopeProject)] = lineage.ProjectID
	}
	return resource
}

func (s *Server) hierarchyABACDenies(ctx context.Context, principal *auth.Principal, permission string, lineage auth.ResourceLineage) (bool, error) {
	// RBAC already ran at a FINER scope (Principal.HasAt on the resolved
	// lineage) before this call; the door applies the tenant boundary and the
	// ABAC deny layer (auth.RBACPreverified documents exactly that).
	reason, err := s.decide(ctx, principal, permission, auth.RBACPreverified, hierarchyResource(principal, lineage))
	if err != nil {
		return false, err
	}
	return reason != auth.DecisionAllowed, nil
}

func (s *Server) loadHierarchy(ctx context.Context, sc tenancy.Scope, principal *auth.Principal) ([]hierarchyOrganization, error) {
	orgs, err := store.Organizations{}.List(ctx, sc)
	if err != nil {
		return nil, err
	}
	out := make([]hierarchyOrganization, 0, len(orgs))
	for _, org := range orgs {
		orgLineage := auth.ResourceLineage{OrganizationID: org.ID}
		orgVisible := principal.HasAt(permOrgRead, orgLineage)
		if orgVisible {
			denied, err := s.hierarchyABACDenies(ctx, principal, permOrgRead, orgLineage)
			if err != nil {
				return nil, err
			}
			orgVisible = !denied
		}
		teams, err := store.Teams{}.ListByOrg(ctx, sc, org.ID)
		if err != nil {
			return nil, err
		}
		ho := hierarchyOrganization{Organization: org, Teams: make([]hierarchyTeam, 0, len(teams))}
		for _, team := range teams {
			teamLineage := auth.ResourceLineage{OrganizationID: org.ID, TeamID: team.ID}
			teamVisible := principal.HasAt(permOrgRead, teamLineage)
			if teamVisible {
				denied, err := s.hierarchyABACDenies(ctx, principal, permOrgRead, teamLineage)
				if err != nil {
					return nil, err
				}
				teamVisible = !denied
			}
			projects, err := store.Projects{}.ListByTeam(ctx, sc, team.ID)
			if err != nil {
				return nil, err
			}
			visibleProjects := make([]store.Project, 0, len(projects))
			for _, project := range projects {
				projectLineage := auth.ResourceLineage{
					OrganizationID: org.ID,
					TeamID:         team.ID,
					ProjectID:      project.ID,
				}
				if !principal.HasAt(permOrgRead, projectLineage) {
					continue
				}
				denied, err := s.hierarchyABACDenies(ctx, principal, permOrgRead, projectLineage)
				if err != nil {
					return nil, err
				}
				if !denied {
					visibleProjects = append(visibleProjects, project)
				}
			}
			if teamVisible || len(visibleProjects) > 0 {
				ho.Teams = append(ho.Teams, hierarchyTeam{Team: team, Projects: visibleProjects})
			}
		}
		if orgVisible || len(ho.Teams) > 0 {
			out = append(out, ho)
		}
	}
	return out, nil
}

func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("hierarchy store is not configured")
	}
	in, err := decodeHierarchyCreate(r)
	if err != nil {
		return err
	}
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil || !principal.Has(permOrgWrite) {
		return apierror.Forbidden("tenant-wide permission required: " + permOrgWrite)
	}
	var created *store.Organization
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		denied, e := s.hierarchyABACDenies(ctx, principal, permOrgWrite, auth.ResourceLineage{})
		if e != nil {
			return e
		}
		if denied {
			return apierror.Forbidden("denied by an attribute policy: " + permOrgWrite)
		}
		created, e = store.Organizations{}.Create(ctx, sc, in.Slug, in.Name)
		if e != nil {
			return mapHierarchyStoreError(e)
		}
		return s.recordAudit(ctx, sc, r, "directory.hierarchy_org_create", created.ID, map[string]any{"slug": created.Slug, "name": created.Name})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/hierarchy/orgs/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("hierarchy store is not configured")
	}
	orgID := r.PathValue("id")
	in, err := decodeHierarchyCreate(r)
	if err != nil {
		return err
	}
	var created *store.Team
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		org, e := (store.Organizations{}).Get(ctx, sc, orgID)
		if e != nil {
			return e
		}
		principal := auth.PrincipalFrom(r.Context())
		lineage := auth.ResourceLineage{OrganizationID: org.ID}
		if principal == nil || !principal.HasAt(permOrgWrite, lineage) {
			return apierror.Forbidden("permission does not cover organization")
		}
		denied, e := s.hierarchyABACDenies(ctx, principal, permOrgWrite, lineage)
		if e != nil {
			return e
		}
		if denied {
			return apierror.Forbidden("denied by an attribute policy: " + permOrgWrite)
		}
		created, e = store.Teams{}.Create(ctx, sc, orgID, in.Slug, in.Name)
		if e != nil {
			return mapHierarchyStoreError(e)
		}
		return s.recordAudit(ctx, sc, r, "directory.hierarchy_team_create", created.ID, map[string]any{
			"org_id": orgID, "slug": created.Slug, "name": created.Name,
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/hierarchy/orgs/"+orgID+"/teams/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("hierarchy store is not configured")
	}
	teamID := r.PathValue("id")
	in, err := decodeHierarchyCreate(r)
	if err != nil {
		return err
	}
	var created *store.Project
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		team, e := (store.Teams{}).Get(ctx, sc, teamID)
		if e != nil {
			return e
		}
		principal := auth.PrincipalFrom(r.Context())
		lineage := auth.ResourceLineage{
			OrganizationID: team.OrgID,
			TeamID:         team.ID,
		}
		if principal == nil || !principal.HasAt(permOrgWrite, lineage) {
			return apierror.Forbidden("permission does not cover team")
		}
		denied, e := s.hierarchyABACDenies(ctx, principal, permOrgWrite, lineage)
		if e != nil {
			return e
		}
		if denied {
			return apierror.Forbidden("denied by an attribute policy: " + permOrgWrite)
		}
		created, e = store.Projects{}.Create(ctx, sc, teamID, in.Slug, in.Name)
		if e != nil {
			return mapHierarchyStoreError(e)
		}
		return s.recordAudit(ctx, sc, r, "directory.hierarchy_project_create", created.ID, map[string]any{
			"team_id": teamID, "slug": created.Slug, "name": created.Name,
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/hierarchy/teams/"+teamID+"/projects/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func decodeHierarchyCreate(r *http.Request) (hierarchyCreateRequest, error) {
	var in hierarchyCreateRequest
	if err := decodeJSON(r, &in); err != nil {
		return in, err
	}
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = strings.TrimSpace(in.Name)
	if in.Slug == "" {
		return in, apierror.Validation("slug is required")
	}
	if in.Name == "" {
		return in, apierror.Validation("name is required")
	}
	return in, nil
}

func mapHierarchyStoreError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505":
		return apierror.Conflict("hierarchy slug already exists").Wrap(err)
	case "23503":
		return apierror.NotFound("parent hierarchy resource not found").Wrap(err)
	default:
		return err
	}
}
