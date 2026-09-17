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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// MCPTokens persists MCP bearer tokens (S25, F14). Like sessions, the auth lookup
// is PRE-TENANT — a token determines its own tenant — so the table carries
// tenant_id but is keyed for auth by the token's hash. Only the hash is stored,
// never the token, so a database read cannot mint a valid token.
type MCPTokens struct{ pool *pgxpool.Pool }

// NewMCPTokens binds the repository to the pool. Direct table operations are
// tenant-scoped; Authenticate uses a narrow pre-tenant database function.
func NewMCPTokens(pool *pgxpool.Pool) MCPTokens { return MCPTokens{pool: pool} }

// ErrInvalidToken is returned when a token hash does not resolve to a live token.
var ErrInvalidToken = errors.New("store: invalid or revoked mcp token")

// Create stores a new token (by hash) for a user in a tenant and returns its id.
func (m MCPTokens) Create(ctx context.Context, tenantID, userID, name string, tokenHash []byte) (string, error) {
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), m.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx,
			`INSERT INTO mcp_tokens (tenant_id, user_id, name, token_hash)
			 VALUES ($1, $2, $3, $4) RETURNING id::text`,
			tenantID, userID, name, tokenHash,
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

// Authenticate resolves a token hash to its (tenant, user), rejecting revoked
// tokens, and stamps last_used_at. It is pre-tenant: the token is the tenant
// selector, and the row holds only tenant_id + user_id (no secret).
func (m MCPTokens) Authenticate(ctx context.Context, tokenHash []byte) (tenantID, userID string, err error) {
	tenantID, err = resolveCredential(ctx, m.pool, credentialMCP, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrInvalidToken
	}
	if err != nil {
		return "", "", err
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		m.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			// DPR-096: verify by reading; the last-used stamp is best-effort so
			// a read-only standby or a fenced writer pool never turns into 401s.
			if err := sc.Q.QueryRow(ctx,
				`SELECT user_id::text FROM mcp_tokens
				  WHERE token_hash = $1
				    AND tenant_id = $2
				    AND revoked_at IS NULL`,
				tokenHash, tenantID,
			).Scan(&userID); err != nil {
				return err
			}
			touchCredential(ctx, sc.Q,
				`UPDATE mcp_tokens SET last_used_at = now()
				  WHERE token_hash = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
				tokenHash, tenantID)
			return nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrInvalidToken
	}
	return tenantID, userID, err
}
