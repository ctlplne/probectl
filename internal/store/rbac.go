package store

import (
	"context"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
	var r Role
	err := scanRole(s.Q.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, slug, name, description) VALUES ($1, $2, $3, $4) RETURNING `+roleCols,
		s.Tenant.String(), slug, name, description), &r)
	if err != nil {
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

// GetBySlug returns a role by slug within the tenant.
func (Roles) GetBySlug(ctx context.Context, s tenancy.Scope, slug string) (*Role, error) {
	var r Role
	if err := scanRole(s.Q.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE slug = $1`, slug), &r); err != nil {
		return nil, notFound("role", err)
	}
	return &r, nil
}

// Delete removes a non-system role (its bindings cascade via the FK).
func (Roles) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND is_system = false`, id)
	return err
}

// List returns the tenant's roles.
func (Roles) List(ctx context.Context, s tenancy.Scope) ([]Role, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+roleCols+` FROM roles ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		if err := scanRole(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
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

// CountForSubject returns how many role bindings a subject has (used in S18).
func (RoleBindings) CountForSubject(ctx context.Context, s tenancy.Scope, subjectType, subjectID string) (int, error) {
	var n int
	err := s.Q.QueryRow(ctx,
		`SELECT count(*) FROM role_bindings WHERE subject_type = $1 AND subject_id = $2`,
		subjectType, subjectID).Scan(&n)
	return n, err
}

// Bind idempotently binds a subject to a role at tenant scope — the SCIM
// group-membership "add member" operation.
func (RoleBindings) Bind(ctx context.Context, s tenancy.Scope, subjectType, subjectID, roleID string) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO role_bindings (tenant_id, subject_type, subject_id, role_id, scope_type)
		 VALUES ($1, $2, $3, $4, 'tenant')
		 ON CONFLICT (tenant_id, subject_type, subject_id, role_id, scope_type, scope_id) DO NOTHING`,
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
