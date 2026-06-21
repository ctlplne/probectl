// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// OTLPTokens persists OTLP bearer tokens (WIRE-008). Like MCP and SCIM tokens,
// the auth lookup is PRE-TENANT — a token determines its own tenant — and only
// the hash is stored (never the plaintext). Normal admin reads/writes run inside
// tenant-scoped RLS transactions; the pre-tenant hash lookup goes through the
// narrow otlp_authenticate_token() SECURITY DEFINER function from migration
// 0048, so an unset tenant GUC fails closed for direct table access.
//
// The token hash is computed by the caller via internal/crypto (FIPS guardrail
// 3); this store is hash-only.
type OTLPTokens struct{ pool *pgxpool.Pool }

// NewOTLPTokens binds the repository to the pool.
func NewOTLPTokens(pool *pgxpool.Pool) OTLPTokens { return OTLPTokens{pool: pool} }

// ErrInvalidOTLPToken is returned when a token hash does not resolve to a live token.
var ErrInvalidOTLPToken = errors.New("store: invalid or revoked otlp token")

// OTLPToken is the metadata record returned to operators (never the hash).
type OTLPToken struct {
	ID         string
	TenantID   string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Create stores a new OTLP token (by hash) for a tenant and returns its id.
func (o OTLPTokens) Create(ctx context.Context, tenantID, name string, tokenHash []byte) (string, error) {
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), o.pool, func(ctx context.Context, s tenancy.Scope) error {
		var createErr error
		id, createErr = o.CreateScoped(ctx, s, name, tokenHash)
		return createErr
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// CreateScoped stores a token inside the caller's tenant transaction. Use this
// from mutation handlers that must commit the token row and audit row together.
func (o OTLPTokens) CreateScoped(ctx context.Context, s tenancy.Scope, name string, tokenHash []byte) (string, error) {
	var id string
	if err := s.Q.QueryRow(ctx,
		`INSERT INTO otlp_tokens (tenant_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id::text`,
		s.Tenant.String(), name, tokenHash).Scan(&id); err != nil {
		return "", mapWriteErr("otlp_token", err)
	}
	return id, nil
}

// Authenticate resolves a token hash to its tenant, rejecting revoked tokens,
// and stamps last_used_at. Pre-tenant: the token selects the tenant.
func (o OTLPTokens) Authenticate(ctx context.Context, tokenHash []byte) (tenantID string, err error) {
	err = o.pool.QueryRow(ctx,
		`SELECT tenant_id::text FROM otlp_authenticate_token($1)`, tokenHash).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidOTLPToken
	}
	return tenantID, err
}

// List returns a tenant's OTLP tokens (metadata only — never the hash).
func (o OTLPTokens) List(ctx context.Context, tenantID string) ([]OTLPToken, error) {
	var out []OTLPToken
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), o.pool, func(ctx context.Context, s tenancy.Scope) error {
		var listErr error
		out, listErr = o.ListScoped(ctx, s)
		return listErr
	})
	return out, err
}

// ListScoped returns token metadata through the caller's tenant-scoped RLS
// transaction. The query intentionally has no tenant predicate: storage-layer
// isolation, not handler filtering, is the outer boundary.
func (o OTLPTokens) ListScoped(ctx context.Context, s tenancy.Scope) ([]OTLPToken, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT id::text, tenant_id::text, name, created_at, last_used_at, revoked_at
		 FROM otlp_tokens ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OTLPToken{}
	for rows.Next() {
		var t OTLPToken
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke marks a tenant's OTLP token revoked (immediate, no restart required).
func (o OTLPTokens) Revoke(ctx context.Context, tenantID, id string) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), o.pool, func(ctx context.Context, s tenancy.Scope) error {
		return o.RevokeScoped(ctx, s, id)
	})
}

// RevokeScoped marks a tenant's OTLP token revoked inside the caller's tenant
// transaction. Use this when the revocation and audit row must be atomic.
func (o OTLPTokens) RevokeScoped(ctx context.Context, s tenancy.Scope, id string) error {
	tag, err := s.Q.Exec(ctx,
		`UPDATE otlp_tokens SET revoked_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		s.Tenant.String(), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidOTLPToken
	}
	return nil
}
