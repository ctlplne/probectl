package store

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// The Tenant → Organization → Team → Project hierarchy. These repositories are
// tenant-scoped: every method runs inside a tenancy.Scope, so Row-Level Security
// confines reads and writes to the caller's tenant. INSERTs stamp tenant_id from
// the scope (which RLS WITH CHECK also verifies); SELECTs rely on RLS for
// filtering rather than per-query predicates.

// Organizations is the tenant-scoped organization repository.
type Organizations struct{}

const orgCols = `id::text, tenant_id::text, slug, name, created_at, updated_at`

// Create inserts an organization in the caller's tenant.
func (Organizations) Create(ctx context.Context, s tenancy.Scope, slug, name string) (*Organization, error) {
	var o Organization
	err := s.Q.QueryRow(ctx,
		`INSERT INTO organizations (tenant_id, slug, name) VALUES ($1, $2, $3) RETURNING `+orgCols,
		s.Tenant.String(), slug, name,
	).Scan(&o.ID, &o.TenantID, &o.Slug, &o.Name, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// Get returns an organization by id (RLS guarantees it belongs to the tenant).
func (Organizations) Get(ctx context.Context, s tenancy.Scope, id string) (*Organization, error) {
	var o Organization
	err := s.Q.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE id = $1`, id).
		Scan(&o.ID, &o.TenantID, &o.Slug, &o.Name, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, notFound("organization", err)
	}
	return &o, nil
}

// List returns the tenant's organizations.
func (Organizations) List(ctx context.Context, s tenancy.Scope) ([]Organization, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+orgCols+` FROM organizations ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.TenantID, &o.Slug, &o.Name, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Teams is the tenant-scoped team repository.
type Teams struct{}

const teamCols = `id::text, tenant_id::text, org_id::text, slug, name, created_at, updated_at`

// Create inserts a team under an organization in the caller's tenant.
func (Teams) Create(ctx context.Context, s tenancy.Scope, orgID, slug, name string) (*Team, error) {
	var t Team
	err := s.Q.QueryRow(ctx,
		`INSERT INTO teams (tenant_id, org_id, slug, name) VALUES ($1, $2, $3, $4) RETURNING `+teamCols,
		s.Tenant.String(), orgID, slug, name,
	).Scan(&t.ID, &t.TenantID, &t.OrgID, &t.Slug, &t.Name, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Get returns a team by id.
func (Teams) Get(ctx context.Context, s tenancy.Scope, id string) (*Team, error) {
	var t Team
	err := s.Q.QueryRow(ctx, `SELECT `+teamCols+` FROM teams WHERE id = $1`, id).
		Scan(&t.ID, &t.TenantID, &t.OrgID, &t.Slug, &t.Name, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, notFound("team", err)
	}
	return &t, nil
}

// ListByOrg returns the teams in an organization.
func (Teams) ListByOrg(ctx context.Context, s tenancy.Scope, orgID string) ([]Team, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+teamCols+` FROM teams WHERE org_id = $1 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Team
	for rows.Next() {
		var t Team
		if err := rows.Scan(&t.ID, &t.TenantID, &t.OrgID, &t.Slug, &t.Name, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Projects is the tenant-scoped project repository.
type Projects struct{}

const projectCols = `id::text, tenant_id::text, team_id::text, slug, name, created_at, updated_at`

// Create inserts a project under a team in the caller's tenant.
func (Projects) Create(ctx context.Context, s tenancy.Scope, teamID, slug, name string) (*Project, error) {
	var p Project
	err := s.Q.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, $4) RETURNING `+projectCols,
		s.Tenant.String(), teamID, slug, name,
	).Scan(&p.ID, &p.TenantID, &p.TeamID, &p.Slug, &p.Name, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Get returns a project by id.
func (Projects) Get(ctx context.Context, s tenancy.Scope, id string) (*Project, error) {
	var p Project
	err := s.Q.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id = $1`, id).
		Scan(&p.ID, &p.TenantID, &p.TeamID, &p.Slug, &p.Name, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, notFound("project", err)
	}
	return &p, nil
}

// ListByTeam returns the projects in a team.
func (Projects) ListByTeam(ctx context.Context, s tenancy.Scope, teamID string) ([]Project, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+projectCols+` FROM projects WHERE team_id = $1 ORDER BY created_at`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.TenantID, &p.TeamID, &p.Slug, &p.Name, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
