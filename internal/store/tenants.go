// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Tenants is the provider-level repository for the tenant registry. It operates
// on the pool directly (the tenants table is global, not tenant-owned), so
// creating and listing tenants is a provider-plane operation (F51), never
// reachable from a tenant-scoped path.
type Tenants struct{ pool *pgxpool.Pool }

// NewTenants returns a provider-level tenant repository.
func NewTenants(pool *pgxpool.Pool) *Tenants { return &Tenants{pool: pool} }

const tenantCols = `id::text, slug, name, status, created_at, updated_at`

func scanTenant(row interface{ Scan(...any) error }, t *Tenant) error {
	return row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt)
}

// Create inserts a new tenant.
func (r *Tenants) Create(ctx context.Context, slug, name string) (*Tenant, error) {
	var t Tenant
	err := scanTenant(r.pool.QueryRow(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING `+tenantCols, slug, name), &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// get returns a tenant by id.
func (r *Tenants) get(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	if err := scanTenant(r.pool.QueryRow(ctx,
		`SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id), &t); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}

// getBySlug returns a tenant by its unique slug.
func (r *Tenants) getBySlug(ctx context.Context, slug string) (*Tenant, error) {
	var t Tenant
	if err := scanTenant(r.pool.QueryRow(ctx,
		`SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug), &t); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}

// List returns all tenants (provider-plane view).
func (r *Tenants) List(ctx context.Context) ([]Tenant, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := scanTenant(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateStatus transitions a tenant's lifecycle status (provision/suspend/offboard).
func (r *Tenants) UpdateStatus(ctx context.Context, id, status string) (*Tenant, error) {
	var t Tenant
	if err := scanTenant(r.pool.QueryRow(ctx,
		`UPDATE tenants SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+tenantCols,
		id, status), &t); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}
