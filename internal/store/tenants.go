// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Tenants is the provider-level repository for the tenant registry. The
// tenants table is global, not tenant-owned, and readable only as the provider
// role, so every method runs in a provider transaction (F51, TEN-01) and is
// never reachable from a tenant-scoped path.
type Tenants struct{ pool *pgxpool.Pool }

// NewTenants returns a provider-level tenant repository.
func NewTenants(pool *pgxpool.Pool) *Tenants { return &Tenants{pool: pool} }

func (r *Tenants) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	return tenancy.InProvider(ctx, r.pool, fn)
}

const tenantCols = `id::text, slug, name, status, created_at, updated_at`

func scanTenant(row interface{ Scan(...any) error }, t *Tenant) error {
	return row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt)
}

// Create inserts a new tenant.
func (r *Tenants) Create(ctx context.Context, slug, name string) (*Tenant, error) {
	var t Tenant
	err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING `+tenantCols, slug, name), &t)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// get returns a tenant by id.
func (r *Tenants) get(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	if err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id), &t)
	}); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}

// getBySlug returns a tenant by its unique slug.
func (r *Tenants) getBySlug(ctx context.Context, slug string) (*Tenant, error) {
	var t Tenant
	if err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug), &t)
	}); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}

// List returns all tenants (provider-plane view).
func (r *Tenants) List(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Tenant
			if err := scanTenant(rows, &t); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateStatus transitions a tenant's lifecycle status (provision/suspend/offboard).
func (r *Tenants) UpdateStatus(ctx context.Context, id, status string) (*Tenant, error) {
	var t Tenant
	if err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return scanTenant(q.QueryRow(ctx,
			`UPDATE tenants SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+tenantCols,
			id, status), &t)
	}); err != nil {
		return nil, notFound("tenant", err)
	}
	return &t, nil
}

// BusNamespaceTenants (DPR-049) maps every active tenant's bus namespace
// (tenancy.BusNamespaceFor(slug)) to its id, so the control plane subscribes
// to and creates a lane per tenant — pooled tenants included — and a
// collector's namespaced batch can be bound to its tenant.
func (r *Tenants) BusNamespaceTenants(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	err := r.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT id::text, slug FROM tenants WHERE status NOT IN ('offboarding', 'deleted')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, slug string
			if err := rows.Scan(&id, &slug); err != nil {
				return err
			}
			out[tenancy.BusNamespaceFor(slug)] = id
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BusNamespace returns the tenant's lane namespace (DPR-049) — the value a
// collector sets as PROBECTL_<PLANE>_BUS_NAMESPACE.
func (r *Tenants) BusNamespace(ctx context.Context, id string) (string, error) {
	t, err := r.get(ctx, id)
	if err != nil {
		return "", err
	}
	return tenancy.BusNamespaceFor(t.Slug), nil
}
