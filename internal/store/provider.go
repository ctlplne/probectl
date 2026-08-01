// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Provider-plane repositories operate on global tables via the pool directly —
// they are a distinct privilege domain from tenant data (F51). Provider operators
// are NOT tenant users, and managing a tenant never grants read access to its
// telemetry; that requires a break-glass grant.

// Operators is the provider-operator repository.
type Operators struct{ pool *pgxpool.Pool }

// newOperators returns the provider-operator repository.
func newOperators(pool *pgxpool.Pool) *Operators { return &Operators{pool: pool} }

const operatorCols = `id::text, email, name, status, created_at, updated_at`

func scanOperator(row interface{ Scan(...any) error }, o *ProviderOperator) error {
	return row.Scan(&o.ID, &o.Email, &o.Name, &o.Status, &o.CreatedAt, &o.UpdatedAt)
}

// create adds a provider operator.
func (r *Operators) create(ctx context.Context, email, name string) (*ProviderOperator, error) {
	var o ProviderOperator
	err := scanOperator(r.pool.QueryRow(ctx,
		`INSERT INTO provider_operators (email, name) VALUES ($1, $2) RETURNING `+operatorCols,
		email, name), &o)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// get returns a provider operator by id.
func (r *Operators) get(ctx context.Context, id string) (*ProviderOperator, error) {
	var o ProviderOperator
	if err := scanOperator(r.pool.QueryRow(ctx,
		`SELECT `+operatorCols+` FROM provider_operators WHERE id = $1`, id), &o); err != nil {
		return nil, notFound("provider operator", err)
	}
	return &o, nil
}

// list returns all provider operators.
func (r *Operators) list(ctx context.Context) ([]ProviderOperator, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+operatorCols+` FROM provider_operators ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProviderOperator
	for rows.Next() {
		var o ProviderOperator
		if err := scanOperator(rows, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// BreakGlass is the break-glass grant repository (the audited, time-bounded path
// by which a provider operator may access one tenant's data).
type BreakGlass struct{ pool *pgxpool.Pool }

// newBreakGlass returns the break-glass repository.
func newBreakGlass(pool *pgxpool.Pool) *BreakGlass { return &BreakGlass{pool: pool} }

const grantCols = `id::text, operator_id::text, tenant_id::text, reason, scope, granted_by, granted_at, expires_at, revoked_at, revoked_by`

func scanGrant(row interface{ Scan(...any) error }, g *BreakGlassGrant) error {
	return row.Scan(&g.ID, &g.OperatorID, &g.TenantID, &g.Reason, &g.Scope,
		&g.GrantedBy, &g.GrantedAt, &g.ExpiresAt, &g.RevokedAt, &g.RevokedBy)
}

// grant creates a time-bounded break-glass grant. The caller should record a
// provider audit event for the grant (internal/audit).
func (r *BreakGlass) grant(ctx context.Context, operatorID, tenantID, reason, scope, grantedBy string, expiresAt time.Time) (*BreakGlassGrant, error) {
	var g BreakGlassGrant
	err := scanGrant(r.pool.QueryRow(ctx,
		`INSERT INTO break_glass_grants (operator_id, tenant_id, reason, scope, granted_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+grantCols,
		operatorID, tenantID, reason, scope, grantedBy, expiresAt), &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// listActive returns the currently-valid grants for a tenant (not revoked, not
// expired).
func (r *BreakGlass) listActive(ctx context.Context, tenantID string) ([]BreakGlassGrant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+grantCols+` FROM break_glass_grants
		 WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY granted_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassGrant
	for rows.Next() {
		var g BreakGlassGrant
		if err := scanGrant(rows, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// revoke ends a grant early.
func (r *BreakGlass) revoke(ctx context.Context, id, revokedBy string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE break_glass_grants SET revoked_at = now(), revoked_by = $2
		 WHERE id = $1 AND revoked_at IS NULL`, id, revokedBy)
	return err
}
