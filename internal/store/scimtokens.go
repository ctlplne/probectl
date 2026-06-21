// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// ScimTokens persists SCIM bearer tokens (S31, F25). The IdP presents one to
// /scim/v2; like sessions, the auth lookup is PRE-TENANT — the token selects its
// own tenant — and only the hash is stored, so a database read cannot mint a
// token. A SCIM token authenticates the directory service to a TENANT (not a
// user): SCIM acts as the provisioning system, not a person. Normal admin
// reads/writes run inside tenant-scoped RLS transactions; the pre-tenant
// Authenticate path is the only narrow table lookup before the tenant is known.
type ScimTokens struct{ pool *pgxpool.Pool }

// NewScimTokens binds the repository to the pool (the pre-tenant auth path).
func NewScimTokens(pool *pgxpool.Pool) ScimTokens { return ScimTokens{pool: pool} }

// ErrInvalidScimToken is returned when a token hash does not resolve to a live token.
var ErrInvalidScimToken = errors.New("store: invalid or revoked scim token")

// Create stores a new SCIM token (by hash) for a tenant and returns its id.
func (s ScimTokens) Create(ctx context.Context, tenantID, name string, tokenHash []byte) (string, error) {
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var createErr error
		id, createErr = s.CreateScoped(ctx, sc, name, tokenHash)
		return createErr
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// CreateScoped stores a token inside the caller's tenant transaction. Use this
// from mutation handlers that must commit the token row and audit row together.
func (s ScimTokens) CreateScoped(ctx context.Context, sc tenancy.Scope, name string, tokenHash []byte) (string, error) {
	var id string
	if err := sc.Q.QueryRow(ctx,
		`INSERT INTO scim_tokens (tenant_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id::text`,
		sc.Tenant.String(), name, tokenHash).Scan(&id); err != nil {
		return "", mapWriteErr("scim_token", err)
	}
	return id, nil
}

// Authenticate resolves a token hash to its tenant, rejecting revoked tokens, and
// stamps last_used_at. Pre-tenant: the token is the tenant selector.
func (s ScimTokens) Authenticate(ctx context.Context, tokenHash []byte) (tenantID string, err error) {
	err = s.pool.QueryRow(ctx,
		`UPDATE scim_tokens SET last_used_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL
		 RETURNING tenant_id::text`, tokenHash).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidScimToken
	}
	return tenantID, err
}

// List returns a tenant's SCIM tokens (metadata only — never the hash).
func (s ScimTokens) List(ctx context.Context, tenantID string) ([]ScimToken, error) {
	var out []ScimToken
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var listErr error
		out, listErr = s.ListScoped(ctx, sc)
		return listErr
	})
	return out, err
}

// ListScoped returns token metadata through the caller's tenant-scoped RLS
// transaction. The query intentionally has no tenant predicate: storage-layer
// isolation, not handler filtering, is the outer boundary.
func (s ScimTokens) ListScoped(ctx context.Context, sc tenancy.Scope) ([]ScimToken, error) {
	rows, err := sc.Q.Query(ctx,
		`SELECT id::text, tenant_id::text, name, created_at, last_used_at, revoked_at
		 FROM scim_tokens ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScimToken{}
	for rows.Next() {
		var t ScimToken
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke marks a tenant's SCIM token revoked.
func (s ScimTokens) Revoke(ctx context.Context, tenantID, id string) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return s.RevokeScoped(ctx, sc, id)
	})
}

// RevokeScoped marks a tenant's SCIM token revoked inside the caller's tenant
// transaction. Use this when the revocation and audit row must be atomic.
func (s ScimTokens) RevokeScoped(ctx context.Context, sc tenancy.Scope, id string) error {
	tag, err := sc.Q.Exec(ctx,
		`UPDATE scim_tokens SET revoked_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		sc.Tenant.String(), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidScimToken
	}
	return nil
}
