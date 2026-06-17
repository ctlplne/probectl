// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OTLPTokens persists OTLP bearer tokens (WIRE-008). Like MCP and SCIM tokens,
// the auth lookup is PRE-TENANT — a token determines its own tenant — and only
// the hash is stored (never the plaintext). Tokens survive restarts and can be
// revoked via the admin API without a config change or process restart.
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
	if err := o.pool.QueryRow(ctx,
		`INSERT INTO otlp_tokens (tenant_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id::text`,
		tenantID, name, tokenHash).Scan(&id); err != nil {
		return "", mapWriteErr("otlp_token", err)
	}
	return id, nil
}

// Authenticate resolves a token hash to its tenant, rejecting revoked tokens,
// and stamps last_used_at. Pre-tenant: the token selects the tenant.
func (o OTLPTokens) Authenticate(ctx context.Context, tokenHash []byte) (tenantID string, err error) {
	err = o.pool.QueryRow(ctx,
		`UPDATE otlp_tokens SET last_used_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL
		 RETURNING tenant_id::text`, tokenHash).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidOTLPToken
	}
	return tenantID, err
}

// List returns a tenant's OTLP tokens (metadata only — never the hash). The
// table has no RLS (pre-tenant auth), so the tenant filter is explicit.
func (o OTLPTokens) List(ctx context.Context, tenantID string) ([]OTLPToken, error) {
	rows, err := o.pool.Query(ctx,
		`SELECT id::text, tenant_id::text, name, created_at, last_used_at, revoked_at
		 FROM otlp_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
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
// The explicit tenant filter ensures a tenant cannot revoke another's token.
func (o OTLPTokens) Revoke(ctx context.Context, tenantID, id string) error {
	tag, err := o.pool.Exec(ctx,
		`UPDATE otlp_tokens SET revoked_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidOTLPToken
	}
	return nil
}

// LoadActive returns all currently-active (unrevoked) tokens for populating
// the in-process authenticator at startup. Returns pairs of (token_hash, tenant_id).
func (o OTLPTokens) LoadActive(ctx context.Context) (hashes [][]byte, tenants []string, err error) {
	rows, err := o.pool.Query(ctx,
		`SELECT token_hash, tenant_id::text FROM otlp_tokens WHERE revoked_at IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h []byte
		var tid string
		if err := rows.Scan(&h, &tid); err != nil {
			return nil, nil, err
		}
		hashes = append(hashes, h)
		tenants = append(tenants, tid)
	}
	return hashes, tenants, rows.Err()
}
