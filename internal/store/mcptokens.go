// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// MCPTokens persists MCP/API bearer tokens (S25, F14; INV-03/RT-02). Like
// sessions, the auth lookup is PRE-TENANT — a token determines its own tenant —
// so the table carries tenant_id but is keyed for auth by the token's hash. Only
// the hash is stored, never the token, so a database read cannot mint a valid
// token. Tokens carry a mandatory expiry (expires_at) and an optional scope
// subset (INV-03/RT-02).
type MCPTokens struct{ pool *pgxpool.Pool }

// NewMCPTokens binds the repository to the pool. Direct table operations are
// tenant-scoped; Authenticate uses a narrow pre-tenant database function.
func NewMCPTokens(pool *pgxpool.Pool) MCPTokens { return MCPTokens{pool: pool} }

// ErrInvalidToken is returned when a token hash does not resolve to a live
// (unrevoked, unexpired) token.
var ErrInvalidToken = errors.New("store: invalid, revoked, or expired mcp token")

// AuthResult carries what a bearer token resolves to. Scopes, when non-empty,
// narrow the owner's effective permissions (INV-03/RT-02). FirstUse is true the
// first time a token authenticates, so the caller can audit it once.
type AuthResult struct {
	TenantID string
	UserID   string
	TokenID  string
	Scopes   []string
	FirstUse bool
}

// TokenInfo is the operator-facing metadata for one token. It never contains the
// token or its hash.
type TokenInfo struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Create stores a new token (by hash) with NO expiry and NO scope restriction —
// the legacy behavior. New callers that mint bounded, scoped tokens use
// CreateWithLifetime (INV-03/RT-02).
func (m MCPTokens) Create(ctx context.Context, tenantID, userID, name string, tokenHash []byte) (string, error) {
	return m.CreateWithLifetime(ctx, tenantID, userID, name, tokenHash, time.Time{}, nil)
}

// CreateWithLifetime stores a new token (by hash) for a user in a tenant and
// returns its id. A zero expiresAt stores NULL (no expiry); the REST API always
// passes a bounded expiry. scopes, when non-empty, is the permission subset the
// token may exercise.
func (m MCPTokens) CreateWithLifetime(ctx context.Context, tenantID, userID, name string, tokenHash []byte, expiresAt time.Time, scopes []string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	var expiry *time.Time
	if !expiresAt.IsZero() {
		e := expiresAt.UTC()
		expiry = &e
	}
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), m.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx,
			`INSERT INTO mcp_tokens (tenant_id, user_id, name, token_hash, expires_at, scopes)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
			tenantID, userID, name, tokenHash, expiry, scopes,
		).Scan(&id); err != nil {
			return err
		}
		return registerCredential(ctx, sc, credentialMCP, id, tokenHash)
	})
	if err != nil {
		return "", mapWriteErr("mcp_token", err)
	}
	return id, nil
}

// List returns the live metadata for every token in a tenant (newest first),
// never the token or its hash. Tenant-scoped (RLS).
func (m MCPTokens) List(ctx context.Context, tenantID string) ([]TokenInfo, error) {
	var out []TokenInfo
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), m.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx,
			`SELECT id::text, user_id::text, name, scopes, created_at, last_used_at, expires_at, revoked_at
			   FROM mcp_tokens
			  WHERE tenant_id = $1
			  ORDER BY created_at DESC`,
			tenantID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ti TokenInfo
			if err := rows.Scan(&ti.ID, &ti.UserID, &ti.Name, &ti.Scopes, &ti.CreatedAt, &ti.LastUsedAt, &ti.ExpiresAt, &ti.RevokedAt); err != nil {
				return err
			}
			if ti.Scopes == nil {
				ti.Scopes = []string{}
			}
			out = append(out, ti)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeByID revokes exactly one token by id, leaving the user's other tokens
// working (INV-03/RT-02). It reports whether a live token with that id existed.
func (m MCPTokens) RevokeByID(ctx context.Context, tenantID, id string) (bool, error) {
	var found bool
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), m.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var hash []byte
		err := sc.Q.QueryRow(ctx,
			`UPDATE mcp_tokens SET revoked_at = now()
			  WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
			  RETURNING token_hash`,
			id, tenantID,
		).Scan(&hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // not found or already revoked
		}
		if err != nil {
			return err
		}
		found = true
		return revokeCredential(ctx, sc, credentialMCP, hash)
	})
	return found, err
}

// RevokeForUser revokes all of a user's MCP tokens in a tenant — part of the SCIM
// deprovision (S31), alongside session revocation.
func (m MCPTokens) RevokeForUser(ctx context.Context, tenantID, userID string) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), m.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx,
			`UPDATE mcp_tokens SET revoked_at = now()
			 WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
			 RETURNING token_hash`,
			tenantID, userID,
		)
		if err != nil {
			return err
		}
		var hashes [][]byte
		for rows.Next() {
			var hash []byte
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			hashes = append(hashes, hash)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, hash := range hashes {
			if err := revokeCredential(ctx, sc, credentialMCP, hash); err != nil {
				return err
			}
		}
		return nil
	})
}

// Authenticate resolves a token hash to its (tenant, user), rejecting revoked OR
// expired tokens. It is the backward-compatible shape; callers that need the
// token's scopes or first-use flag call AuthenticateFull (INV-03/RT-02).
func (m MCPTokens) Authenticate(ctx context.Context, tokenHash []byte) (tenantID, userID string, err error) {
	res, err := m.AuthenticateFull(ctx, tokenHash)
	return res.TenantID, res.UserID, err
}

// AuthenticateFull resolves a token hash to its owner, scopes and first-use
// flag, rejecting revoked OR expired tokens, and stamps last_used_at. It is
// pre-tenant: the token is the tenant selector, and the row holds only
// tenant_id + user_id + metadata (no secret).
func (m MCPTokens) AuthenticateFull(ctx context.Context, tokenHash []byte) (AuthResult, error) {
	tenantID, err := resolveCredential(ctx, m.pool, credentialMCP, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthResult{}, ErrInvalidToken
	}
	if err != nil {
		return AuthResult{}, err
	}
	res := AuthResult{TenantID: tenantID}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		m.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			// DPR-096: verify by reading; the last-used stamp is best-effort so a
			// read-only standby or a fenced writer pool never turns into 401s.
			// INV-03/RT-02: an expired token authenticates to nothing.
			var lastUsed *time.Time
			if err := sc.Q.QueryRow(ctx,
				`SELECT id::text, user_id::text, scopes, last_used_at FROM mcp_tokens
				  WHERE token_hash = $1
				    AND tenant_id = $2
				    AND revoked_at IS NULL
				    AND (expires_at IS NULL OR expires_at > now())`,
				tokenHash, tenantID,
			).Scan(&res.TokenID, &res.UserID, &res.Scopes, &lastUsed); err != nil {
				return err
			}
			res.FirstUse = lastUsed == nil
			if res.Scopes == nil {
				res.Scopes = []string{}
			}
			touchCredential(ctx, sc.Q,
				`UPDATE mcp_tokens SET last_used_at = now()
				  WHERE token_hash = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
				tokenHash, tenantID)
			return nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthResult{}, ErrInvalidToken
	}
	if err != nil {
		return AuthResult{}, err
	}
	return res, nil
}
