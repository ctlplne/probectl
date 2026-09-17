// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// RBAC repositories — SCHEMA-LEVEL only in S2 (enforcement lands in S18). They
// are tenant-scoped: roles and bindings live within a tenant and are RLS-confined.

// Roles is the tenant-scoped role repository.
type Roles struct{}

const roleCols = `id::text, tenant_id::text, slug, name, description, is_system, created_at, updated_at`

func scanRole(row interface{ Scan(...any) error }, r *Role) error {
	return row.Scan(&r.ID, &r.TenantID, &r.Slug, &r.Name, &r.Description, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt)
}

// Create inserts a role in the caller's tenant.
func (Roles) Create(ctx context.Context, s tenancy.Scope, slug, name, description string) (*Role, error) {
	return (Roles{}).CreateLimited(ctx, s, slug, name, description, 0)
}

// CreateLimited inserts a role only while the tenant remains under maxRoles.
// SCIM groups map to roles, so this is the directory group cap boundary.
func (Roles) CreateLimited(ctx context.Context, s tenancy.Scope, slug, name, description string, maxRoles int) (*Role, error) {
	var r Role
	sql := `INSERT INTO roles (tenant_id, slug, name, description) VALUES ($1, $2, $3, $4) RETURNING ` + roleCols
	args := []any{s.Tenant.String(), slug, name, description}
	if maxRoles > 0 {
		sql = `INSERT INTO roles (tenant_id, slug, name, description)
		 SELECT $1, $2, $3, $4
		  WHERE (SELECT count(*) FROM roles) < $5
		 RETURNING ` + roleCols
		args = append(args, maxRoles)
	}
	err := scanRole(s.Q.QueryRow(ctx, sql, args...), &r)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.Validation("tenant SCIM group limit reached").WithCode(string(apierror.CodeQuotaExceeded))
		}
		// DPR-042: a slug collision is a conflict the caller can act on (an
		// IdP looks the existing group up), not an invalid attribute set.
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, apierror.Conflict("role already exists")
		}
		return nil, err
	}
	return &r, nil
}

// Get returns a role by id (a SCIM Group maps to a role).
func (Roles) Get(ctx context.Context, s tenancy.Scope, id string) (*Role, error) {
	var r Role
	if err := scanRole(s.Q.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE id = $1`, id), &r); err != nil {
		return nil, notFound("role", err)
	}
	return &r, nil
}

// getBySlug returns a role by slug within the tenant.
// GetBySlug resolves a tenant role by its stable slug (the seeded system roles
// are admin, editor and viewer).
func (r Roles) GetBySlug(ctx context.Context, s tenancy.Scope, slug string) (*Role, error) {
	return r.getBySlug(ctx, s, slug)
}

func (Roles) getBySlug(ctx context.Context, s tenancy.Scope, slug string) (*Role, error) {
	var r Role
	if err := scanRole(s.Q.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE slug = $1`, slug), &r); err != nil {
		return nil, notFound("role", err)
	}
	return &r, nil
}

// Rename updates a role's human display name (a SCIM Group's displayName).
// The slug — the stable identity bindings and references join on — is
// deliberately untouched, so a rename can never strand a member or collide
// with the UNIQUE (tenant_id, slug) constraint. System roles are not
// renameable through this path (0 rows → not found), mirroring Delete's guard.
func (Roles) Rename(ctx context.Context, s tenancy.Scope, id, name string) (*Role, error) {
	var r Role
	if err := scanRole(s.Q.QueryRow(ctx,
		`UPDATE roles SET name = $2, updated_at = now() WHERE id = $1 AND is_system = false RETURNING `+roleCols,
		id, name), &r); err != nil {
		return nil, notFound("role", err)
	}
	return &r, nil
}

// Delete removes a non-system role (its bindings cascade via the FK).
func (Roles) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND is_system = false`, id)
	return err
}

// list returns the tenant's roles.
func (Roles) list(ctx context.Context, s tenancy.Scope) ([]Role, error) {
	total, err := (Roles{}).Count(ctx, s)
	if err != nil {
		return nil, err
	}
	roles, _, err := (Roles{}).ListPage(ctx, s, 1, total)
	return roles, err
}

// Count returns the tenant's role count.
func (Roles) Count(ctx context.Context, s tenancy.Scope) (int, error) {
	var n int
	if err := s.Q.QueryRow(ctx, `SELECT count(*) FROM roles`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListPage returns a SQL-bounded role page plus the total count. startIndex is
// SCIM's 1-based cursor; count=0 is an empty page.
func (Roles) ListPage(ctx context.Context, s tenancy.Scope, startIndex, count int) ([]Role, int, error) {
	return (Roles{}).ListPageFiltered(ctx, s, "", startIndex, count)
}

// ListPageFiltered is ListPage narrowed to roles whose display name equals
// nameFilter — the SCIM `displayName eq "…"` lookup an IdP runs before it
// binds members (DPR-041). An empty filter lists every role.
func (Roles) ListPageFiltered(ctx context.Context, s tenancy.Scope, nameFilter string, startIndex, count int) ([]Role, int, error) {
	var total int
	countSQL, countArgs := `SELECT count(*) FROM roles`, []any{}
	if nameFilter != "" {
		countSQL += ` WHERE name = $1`
		countArgs = append(countArgs, nameFilter)
	}
	if err := s.Q.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if startIndex < 1 {
		startIndex = 1
	}
	offset := startIndex - 1
	sql := `SELECT ` + roleCols + ` FROM roles`
	args := []any{count, offset}
	if nameFilter != "" {
		sql += ` WHERE name = $3`
		args = append(args, nameFilter)
	}
	sql += ` ORDER BY created_at, id LIMIT $1 OFFSET $2`
	rows, err := s.Q.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		if err := scanRole(rows, &r); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// AddPermission grants a catalog permission to a role (idempotent).
func (Roles) AddPermission(ctx context.Context, s tenancy.Scope, roleID, permissionKey string) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO role_permissions (tenant_id, role_id, permission_key) VALUES ($1, $2, $3)
		 ON CONFLICT (role_id, permission_key) DO NOTHING`,
		s.Tenant.String(), roleID, permissionKey)
	return err
}

// Permissions returns the permission keys granted to a role.
func (Roles) Permissions(ctx context.Context, s tenancy.Scope, roleID string) ([]string, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT permission_key FROM role_permissions WHERE role_id = $1 ORDER BY permission_key`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RoleBindings is the tenant-scoped role-binding repository.
type RoleBindings struct{}

// Create binds a subject (user or service account) to a role at a scope.
func (RoleBindings) Create(ctx context.Context, s tenancy.Scope, subjectType, subjectID, roleID, scopeType string, scopeID *string) (string, error) {
	var id string
	err := s.Q.QueryRow(ctx,
		`INSERT INTO role_bindings (tenant_id, subject_type, subject_id, role_id, scope_type, scope_id)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
		s.Tenant.String(), subjectType, subjectID, roleID, scopeType, scopeID).Scan(&id)
	return id, err
}

// countForSubject returns how many role bindings a subject has (used in S18).
func (RoleBindings) countForSubject(ctx context.Context, s tenancy.Scope, subjectType, subjectID string) (int, error) {
	var n int
	err := s.Q.QueryRow(ctx,
		`SELECT count(*) FROM role_bindings WHERE subject_type = $1 AND subject_id = $2`,
		subjectType, subjectID).Scan(&n)
	return n, err
}

// Bind idempotently binds a subject to a role at tenant scope — the SCIM
// group-membership "add member" operation and the bootstrap-admin grant. The
// conflict target is the partial unique index on the tenant-scope shape
// (migration 0092): the table's full UNIQUE constraint includes the NULL
// scope_id, which PostgreSQL treats as distinct, so it never deduplicated
// (DPR-015).
func (RoleBindings) Bind(ctx context.Context, s tenancy.Scope, subjectType, subjectID, roleID string) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO role_bindings (tenant_id, subject_type, subject_id, role_id, scope_type)
		 VALUES ($1, $2, $3, $4, 'tenant')
		 ON CONFLICT (tenant_id, subject_type, subject_id, role_id)
		 WHERE scope_type = 'tenant' AND scope_id IS NULL DO NOTHING`,
		s.Tenant.String(), subjectType, subjectID, roleID)
	return err
}

// Unbind removes a subject's tenant-scoped binding to a role — the SCIM "remove
// member" operation.
func (RoleBindings) Unbind(ctx context.Context, s tenancy.Scope, subjectType, subjectID, roleID string) error {
	_, err := s.Q.Exec(ctx,
		`DELETE FROM role_bindings
		 WHERE subject_type = $1 AND subject_id = $2 AND role_id = $3 AND scope_type = 'tenant'`,
		subjectType, subjectID, roleID)
	return err
}

// MembersOfRole returns the user ids bound to a role — a SCIM Group's members.
func (RoleBindings) MembersOfRole(ctx context.Context, s tenancy.Scope, roleID string) ([]string, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT subject_id::text FROM role_bindings
		 WHERE role_id = $1 AND subject_type = 'user' ORDER BY created_at`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RolesOfUser returns the roles bound to one user at tenant scope (DPR-027:
// what a tenant administrator sees and edits in the directory).
func (RoleBindings) RolesOfUser(ctx context.Context, s tenancy.Scope, userID string) ([]Role, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT `+roleCols+` FROM roles
		 WHERE id IN (SELECT role_id FROM role_bindings
		              WHERE subject_type = 'user' AND subject_id = $1 AND scope_type = 'tenant')
		 ORDER BY slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		var r Role
		if err := scanRole(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RoleSlugsByUser returns, for every user with a tenant-scope binding, the
// sorted slugs of the roles bound to them — one query for a directory listing.
func (RoleBindings) RoleSlugsByUser(ctx context.Context, s tenancy.Scope) (map[string][]string, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT b.subject_id::text, r.slug FROM role_bindings b
		 JOIN roles r ON r.id = b.role_id
		 WHERE b.subject_type = 'user' AND b.scope_type = 'tenant'
		 ORDER BY b.subject_id, r.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var userID, slug string
		if err := rows.Scan(&userID, &slug); err != nil {
			return nil, err
		}
		out[userID] = append(out[userID], slug)
	}
	return out, rows.Err()
}

// EnsureSystemRoles seeds the tenant's admin/editor/viewer roles and their
// permission sets, idempotently, mirroring migration 0013's rules: admin holds
// every catalog permission, viewer every read, editor reads plus test/alert/
// incident writes. Provisioning calls it when a tenant is published and
// bootstrap-admin calls it before its first grant (DPR-035).
func (Roles) EnsureSystemRoles(ctx context.Context, s tenancy.Scope) error {
	tid := s.Tenant.String()
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO roles (tenant_id, slug, name, description, is_system) VALUES
		   ($1, 'admin',  'Administrator', 'Full access within the tenant', true),
		   ($1, 'editor', 'Editor',        'Read everything; manage tests, alerts, incidents', true),
		   ($1, 'viewer', 'Viewer',        'Read-only', true)
		 ON CONFLICT (tenant_id, slug) DO NOTHING`, tid); err != nil {
		return err
	}
	for _, q := range []string{
		`INSERT INTO role_permissions (tenant_id, role_id, permission_key)
		   SELECT r.tenant_id, r.id, p.key FROM roles r CROSS JOIN permissions p
		   WHERE r.tenant_id = $1 AND r.slug = 'admin' AND r.is_system
		 ON CONFLICT (role_id, permission_key) DO NOTHING`,
		`INSERT INTO role_permissions (tenant_id, role_id, permission_key)
		   SELECT r.tenant_id, r.id, p.key FROM roles r CROSS JOIN permissions p
		   WHERE r.tenant_id = $1 AND r.slug = 'viewer' AND r.is_system AND p.key LIKE '%.read'
		 ON CONFLICT (role_id, permission_key) DO NOTHING`,
		`INSERT INTO role_permissions (tenant_id, role_id, permission_key)
		   SELECT r.tenant_id, r.id, p.key FROM roles r CROSS JOIN permissions p
		   WHERE r.tenant_id = $1 AND r.slug = 'editor' AND r.is_system
		     AND (p.key LIKE '%.read' OR p.key IN ('test.write', 'alert.write', 'incident.write'))
		 ON CONFLICT (role_id, permission_key) DO NOTHING`,
	} {
		if _, err := s.Q.Exec(ctx, q, tid); err != nil {
			return err
		}
	}
	return nil
}
