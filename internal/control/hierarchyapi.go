// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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

// handleGetHierarchy serves the caller tenant's org/team/project tree. Every
// read goes through tenancy.InTenant, so Postgres RLS is the outer boundary.
func (s *Server) handleGetHierarchy(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("hierarchy store is not configured")
	}
	var resp hierarchyResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		tree, err := loadHierarchy(ctx, sc)
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

func loadHierarchy(ctx context.Context, sc tenancy.Scope) ([]hierarchyOrganization, error) {
	orgs, err := store.Organizations{}.List(ctx, sc)
	if err != nil {
		return nil, err
	}
	out := make([]hierarchyOrganization, 0, len(orgs))
	for _, org := range orgs {
		teams, err := store.Teams{}.ListByOrg(ctx, sc, org.ID)
		if err != nil {
			return nil, err
		}
		ho := hierarchyOrganization{Organization: org, Teams: make([]hierarchyTeam, 0, len(teams))}
		for _, team := range teams {
			projects, err := store.Projects{}.ListByTeam(ctx, sc, team.ID)
			if err != nil {
				return nil, err
			}
			if projects == nil {
				projects = []store.Project{}
			}
			ho.Teams = append(ho.Teams, hierarchyTeam{Team: team, Projects: projects})
		}
		out = append(out, ho)
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
	var created *store.Organization
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
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
		if _, e := (store.Organizations{}).Get(ctx, sc, orgID); e != nil {
			return e
		}
		var e error
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
		if _, e := (store.Teams{}).Get(ctx, sc, teamID); e != nil {
			return e
		}
		var e error
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
