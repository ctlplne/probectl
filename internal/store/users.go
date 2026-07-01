// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Users is the tenant-scoped user repository (per-tenant identity; SSO in S18,
// SCIM lifecycle in S31).
type Users struct{}

const userCols = `id::text, tenant_id::text, email, display_name, status,
	external_id, user_name, attributes, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }, u *User) error {
	var ext, uname *string
	var attrs []byte
	if err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status,
		&ext, &uname, &attrs, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return err
	}
	u.ExternalID, u.UserName, u.Attributes = "", "", nil
	if ext != nil {
		u.ExternalID = *ext
	}
	if uname != nil {
		u.UserName = *uname
	}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &u.Attributes); err != nil {
			return fmt.Errorf("store: decode user %s attributes: %w", u.ID, err)
		}
	}
	return nil
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func orEmptyAttrs(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func statusOrActive(s string) string {
	if s == "" {
		return "active"
	}
	return s
}

// Create inserts a user in the caller's tenant (the SSO JIT path; SCIM uses
// CreateSCIM).
func (Users) Create(ctx context.Context, s tenancy.Scope, email, displayName string) (*User, error) {
	var u User
	err := scanUser(s.Q.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name) VALUES ($1, $2, $3) RETURNING `+userCols,
		s.Tenant.String(), email, displayName), &u)
	if err != nil {
		return nil, mapWriteErr("user", err)
	}
	return &u, nil
}

// CreateSCIM provisions a user from a SCIM create (external_id + userName +
// attributes). A duplicate userName/external_id surfaces as a conflict.
func (Users) CreateSCIM(ctx context.Context, s tenancy.Scope, in User) (*User, error) {
	return (Users{}).CreateSCIMLimited(ctx, s, in, 0)
}

// CreateSCIMLimited provisions a SCIM user only while the tenant remains under
// maxUsers. The cap check lives in the INSERT statement so the database, not a
// pre-handler slice, is the growth boundary.
func (Users) CreateSCIMLimited(ctx context.Context, s tenancy.Scope, in User, maxUsers int) (*User, error) {
	attrs, _ := json.Marshal(orEmptyAttrs(in.Attributes))
	var u User
	sql := `INSERT INTO users (tenant_id, email, display_name, status, external_id, user_name, attributes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING ` + userCols
	args := []any{s.Tenant.String(), in.Email, in.DisplayName, statusOrActive(in.Status),
		strOrNil(in.ExternalID), strOrNil(in.UserName), attrs}
	if maxUsers > 0 {
		sql = `INSERT INTO users (tenant_id, email, display_name, status, external_id, user_name, attributes)
		 SELECT $1,$2,$3,$4,$5,$6,$7::jsonb
		  WHERE (SELECT count(*) FROM users) < $8
		 RETURNING ` + userCols
		args = append(args, maxUsers)
	}
	err := scanUser(s.Q.QueryRow(ctx, sql, args...), &u)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierror.Validation("tenant SCIM user limit reached").WithCode(string(apierror.CodeQuotaExceeded))
		}
		return nil, mapWriteErr("user", err)
	}
	return &u, nil
}

// Update replaces a user's mutable fields (SCIM PUT/PATCH).
func (Users) Update(ctx context.Context, s tenancy.Scope, id string, in User) (*User, error) {
	attrs, _ := json.Marshal(orEmptyAttrs(in.Attributes))
	var u User
	err := scanUser(s.Q.QueryRow(ctx,
		`UPDATE users
		   SET email = $2, display_name = $3, status = $4, external_id = $5,
		       user_name = $6, attributes = $7::jsonb, updated_at = now()
		 WHERE id = $1 RETURNING `+userCols,
		id, in.Email, in.DisplayName, statusOrActive(in.Status),
		strOrNil(in.ExternalID), strOrNil(in.UserName), attrs), &u)
	if err != nil {
		return nil, mapWriteErr("user", err)
	}
	return &u, nil
}

// Get returns a user by id.
func (Users) Get(ctx context.Context, s tenancy.Scope, id string) (*User, error) {
	var u User
	if err := scanUser(s.Q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id), &u); err != nil {
		return nil, notFound("user", err)
	}
	return &u, nil
}

// GetByEmail returns a user by email within the tenant.
func (Users) GetByEmail(ctx context.Context, s tenancy.Scope, email string) (*User, error) {
	var u User
	if err := scanUser(s.Q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = $1`, email), &u); err != nil {
		return nil, notFound("user", err)
	}
	return &u, nil
}

// GetByExternalID returns a user by the IdP's external id within the tenant.
func (Users) GetByExternalID(ctx context.Context, s tenancy.Scope, externalID string) (*User, error) {
	var u User
	if err := scanUser(s.Q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE external_id = $1`, externalID), &u); err != nil {
		return nil, notFound("user", err)
	}
	return &u, nil
}

// List returns the tenant's users, optionally filtered by exact userName (the
// SCIM `userName eq` filter).
func (Users) List(ctx context.Context, s tenancy.Scope, userNameFilter string) ([]User, error) {
	total, err := (Users{}).Count(ctx, s, userNameFilter)
	if err != nil {
		return nil, err
	}
	users, _, err := (Users{}).ListPage(ctx, s, userNameFilter, 1, total)
	return users, err
}

// Count returns the number of users visible in the caller's tenant, optionally
// filtered by exact SCIM userName.
func (Users) Count(ctx context.Context, s tenancy.Scope, userNameFilter string) (int, error) {
	sql := `SELECT count(*) FROM users`
	args := []any{}
	if userNameFilter != "" {
		sql += ` WHERE user_name = $1`
		args = append(args, userNameFilter)
	}
	var n int
	if err := s.Q.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListPage returns a SQL-bounded page of tenant users plus the total matching
// count. startIndex is SCIM's 1-based cursor; count=0 is a real empty page.
func (Users) ListPage(ctx context.Context, s tenancy.Scope, userNameFilter string, startIndex, count int) ([]User, int, error) {
	total, err := (Users{}).Count(ctx, s, userNameFilter)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 {
		startIndex = 1
	}
	offset := startIndex - 1
	sql := `SELECT ` + userCols + ` FROM users`
	args := []any{count, offset}
	if userNameFilter != "" {
		sql += ` WHERE user_name = $3`
		args = append(args, userNameFilter)
	}
	sql += ` ORDER BY created_at, id LIMIT $1 OFFSET $2`
	rows, err := s.Q.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := scanUser(rows, &u); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// Delete removes a user (SCIM DELETE → the resource is gone). Sessions/tokens are
// revoked by the caller first.
func (Users) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// UpdateStatus changes a user's status (active/suspended/disabled). Deprovision
// uses status='disabled'.
func (Users) UpdateStatus(ctx context.Context, s tenancy.Scope, id, status string) (*User, error) {
	var u User
	if err := scanUser(s.Q.QueryRow(ctx,
		`UPDATE users SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+userCols,
		id, status), &u); err != nil {
		return nil, notFound("user", err)
	}
	return &u, nil
}
