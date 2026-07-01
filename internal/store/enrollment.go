// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Agent enrollment storage (Sprint 11; ADR docs/adr/agent-enrollment.md).
// Like MCPTokens, the CONSUME path is PRE-TENANT: the token hash IS the
// tenant selector, so that one lookup runs on the bare pool (the 0041 RLS
// policy is permissive with no tenant context, tenant-confined with one —
// U-091). TENANT-009: every KNOWN-TENANT operation (Create, Record,
// KnownSerial, IsAgentRevoked, RevokeAgent) instead runs UNDER tenancy.InTenant
// so RLS confines it — the permissive-on-null policy is reserved strictly for
// the pre-tenant Consume/ListRevoked paths that have no tenant in hand.

// ErrEnrollTokenInvalid is the single, deliberately uninformative refusal for
// every bad-token shape: unknown, replayed, expired, revoked, wrong tenant.
// Fail closed without telling an attacker WHICH check failed.
var ErrEnrollTokenInvalid = errors.New("store: invalid enrollment token")

// EnrollTokens persists one-time agent join tokens (hash only).
type EnrollTokens struct{ pool *pgxpool.Pool }

// NewEnrollTokens binds the repository to the pool (pre-tenant paths).
func NewEnrollTokens(pool *pgxpool.Pool) EnrollTokens { return EnrollTokens{pool: pool} }

// CreatedScoped reports whether this tenant has ever minted an agent enrollment
// token. It intentionally returns only a boolean: the one-time token secret is
// show-once, but first-run progress can still resume after a browser reload.
func (e EnrollTokens) CreatedScoped(ctx context.Context, s tenancy.Scope) (bool, error) {
	var ok bool
	err := s.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_enroll_tokens)`).Scan(&ok)
	return ok, err
}

// Create mints a token row. agentID "" lets the server assign one at
// enrollment; non-empty pins the enrolling agent's identity.
func (e EnrollTokens) Create(ctx context.Context, tenantID, agentID, name, createdBy string, tokenHash []byte, ttl time.Duration) (string, error) {
	// TENANT-009: the caller's tenant is known here, so run UNDER InTenant — RLS
	// confines the write to this tenant (defense in depth above the explicit
	// tenant_id). The permissive-on-null policy is reserved for the pre-tenant
	// token-hash Consume path alone.
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx,
			`INSERT INTO agent_enroll_tokens (tenant_id, agent_id, name, token_hash, created_by, expires_at)
			 VALUES ($1, NULLIF($2,''), $3, $4, $5, now() + $6) RETURNING id::text`,
			tenantID, agentID, name, tokenHash, createdBy, ttl).Scan(&id)
	})
	if err != nil {
		return "", mapWriteErr("agent_enroll_token", err)
	}
	return id, nil
}

// Consume atomically burns the token: exactly one caller can ever win the
// row (used_at IS NULL guard), and a consumed/expired/revoked/unknown token
// is indistinguishable to the caller. Returns the token's tenant and any
// pinned agent id.
func (e EnrollTokens) Consume(ctx context.Context, tokenHash []byte, usedByAgent string) (tenantID, pinnedAgentID string, err error) {
	err = e.pool.QueryRow(ctx,
		`UPDATE agent_enroll_tokens
		    SET used_at = now(), used_by_agent = $2
		  WHERE token_hash = $1
		    AND used_at IS NULL
		    AND revoked_at IS NULL
		    AND expires_at > now()
		 RETURNING tenant_id::text, COALESCE(agent_id, '')`,
		tokenHash, usedByAgent).Scan(&tenantID, &pinnedAgentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrEnrollTokenInvalid
	}
	if err != nil {
		return "", "", err
	}
	return tenantID, pinnedAgentID, nil
}

// ConsumeForTenant atomically burns a token that MUST belong to tenantID. This
// is the tenant-admin API path: unlike the pre-identity /enroll bootstrap, the
// caller already has an authenticated tenant, so RLS must be part of the token
// consume boundary. A foreign-tenant token returns the same uninformative
// ErrEnrollTokenInvalid and is not consumed.
func (e EnrollTokens) ConsumeForTenant(ctx context.Context, tenantID string, tokenHash []byte, usedByAgent string) (pinnedAgentID string, err error) {
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx,
			`UPDATE agent_enroll_tokens
			    SET used_at = now(), used_by_agent = $3
			  WHERE token_hash = $1
			    AND tenant_id = $2
			    AND used_at IS NULL
			    AND revoked_at IS NULL
			    AND expires_at > now()
			 RETURNING COALESCE(agent_id, '')`,
			tokenHash, tenantID, usedByAgent).Scan(&pinnedAgentID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrEnrollTokenInvalid
	}
	if err != nil {
		return "", err
	}
	return pinnedAgentID, nil
}

// Revoke voids an UNUSED token (operator path; a used token is already inert).
// It reports whether a row changed: false means no unredeemed token had that
// id — already redeemed, already revoked, or never existed — so the CLI can
// tell the operator the truth instead of a blind "ok".
func (e EnrollTokens) Revoke(ctx context.Context, id string) (bool, error) {
	tag, err := e.pool.Exec(ctx,
		`UPDATE agent_enroll_tokens SET revoked_at = now() WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// AgentIdentities records every issued SVID — the issuance provenance behind
// the Sprint 4 tenant binding and the serial source for Sprint 12 revocation.
type AgentIdentities struct{ pool *pgxpool.Pool }

// NewAgentIdentities binds the repository to the pool.
func NewAgentIdentities(pool *pgxpool.Pool) AgentIdentities { return AgentIdentities{pool: pool} }

// Record stores one issued leaf. rotatedFrom "" marks first issuance.
func (a AgentIdentities) Record(ctx context.Context, tenantID, agentID, spiffeID, serial string, notAfter time.Time, rotatedFrom string) error {
	// TENANT-009: known tenant => RLS-confined write under InTenant.
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx,
			`INSERT INTO agent_identities (tenant_id, agent_id, spiffe_id, serial, not_after, rotated_from)
			 VALUES ($1, $2, $3, $4, $5, NULLIF($6,''))`,
			tenantID, agentID, spiffeID, serial, notAfter, rotatedFrom)
		return err
	})
	if err != nil {
		return mapWriteErr("agent_identity", err)
	}
	return nil
}

// KnownSerial reports whether a serial was issued by this deployment for the
// given tenant+agent — the rotation path's "this cert is ours" check.
func (a AgentIdentities) KnownSerial(ctx context.Context, tenantID, agentID, serial string) (bool, error) {
	// TENANT-009: known tenant => RLS-confined read under InTenant, so a wrong
	// tenant id can never match another tenant's serial even if the app WHERE
	// were dropped.
	var n int
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx,
			`SELECT count(*) FROM agent_identities WHERE tenant_id = $1 AND agent_id = $2 AND serial = $3`,
			tenantID, agentID, serial).Scan(&n)
	})
	return n > 0, err
}

// AgentCA persists the deployment's agent CA hierarchy: the root CERTIFICATE
// only (its key is exported once at init for offline custody, never stored)
// and the issuing intermediate with its key SEALED via tenantcrypto.
type AgentCA struct{ pool *pgxpool.Pool }

// NewAgentCA binds the repository to the pool.
func NewAgentCA(pool *pgxpool.Pool) AgentCA { return AgentCA{pool: pool} }

// ErrAgentCANotInitialized distinguishes "run agent-ca init" from real errors.
var ErrAgentCANotInitialized = errors.New("store: agent CA not initialized (run: probectl-control agent-ca init)")

// Save upserts one hierarchy row. sealedKey "" stores NULL (the root).
func (c AgentCA) Save(ctx context.Context, kind, certPEM, sealedKey string) error {
	_, err := c.pool.Exec(ctx,
		`INSERT INTO agent_ca (kind, cert_pem, key_sealed) VALUES ($1, $2, NULLIF($3,''))
		 ON CONFLICT (kind) DO UPDATE SET cert_pem = EXCLUDED.cert_pem, key_sealed = EXCLUDED.key_sealed`,
		kind, certPEM, sealedKey)
	return err
}

// Load returns one hierarchy row.
func (c AgentCA) Load(ctx context.Context, kind string) (certPEM, sealedKey string, err error) {
	var sealed *string
	err = c.pool.QueryRow(ctx,
		`SELECT cert_pem, key_sealed FROM agent_ca WHERE kind = $1`, kind).Scan(&certPEM, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrAgentCANotInitialized
	}
	if err != nil {
		return "", "", err
	}
	if sealed != nil {
		sealedKey = *sealed
	}
	return certPEM, sealedKey, nil
}

// RevokeAgent stamps every identity row of (tenant, agent) revoked and
// returns the live serials + the SPIFFE id to feed the handshake deny-list
// (Sprint 12, WIRE-003). Idempotent: re-revoking returns the same material.
// Pre-tenant by design — revocation is an operator action that must also work
// from the CLI; RLS on agent_identities follows the consume-path pattern.
func (a AgentIdentities) RevokeAgent(ctx context.Context, tenantID, agentID, revokedBy string) (serials []string, spiffeID string, err error) {
	// TENANT-009: known tenant => run the whole operator revocation UNDER
	// InTenant so RLS confines every statement to this tenant.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx,
			`UPDATE agent_identities SET revoked_at = now(), revoked_by = $3
			  WHERE tenant_id = $1 AND agent_id = $2 AND revoked_at IS NULL`,
			tenantID, agentID, revokedBy); err != nil {
			return err
		}
		rows, err := sc.Q.Query(ctx,
			`SELECT serial, spiffe_id FROM agent_identities
			  WHERE tenant_id = $1 AND agent_id = $2 AND revoked_at IS NOT NULL AND not_after > now()`,
			tenantID, agentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s, sp string
			if err := rows.Scan(&s, &sp); err != nil {
				return err
			}
			serials = append(serials, s)
			spiffeID = sp
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if spiffeID == "" {
			// No live rows (all expired or none issued): still revoke the IDENTITY
			// so re-enrollment under the same id is refused.
			var count int
			if err := sc.Q.QueryRow(ctx,
				`SELECT count(*) FROM agent_identities WHERE tenant_id=$1 AND agent_id=$2`,
				tenantID, agentID).Scan(&count); err != nil {
				return err
			}
			if count == 0 {
				return fmt.Errorf("store: agent %s has no issued identities in tenant %s", agentID, tenantID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return serials, spiffeID, nil
}

// IsAgentRevoked reports whether (tenant, agent) has been operator-revoked —
// enrollment and rotation refuse a revoked agent id (no resurrection).
func (a AgentIdentities) IsAgentRevoked(ctx context.Context, tenantID, agentID string) (bool, error) {
	// TENANT-009: known tenant => RLS-confined read under InTenant.
	var n int
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx,
			`SELECT count(*) FROM agent_identities
			  WHERE tenant_id = $1 AND agent_id = $2 AND revoked_at IS NOT NULL`,
			tenantID, agentID).Scan(&n)
	})
	return n > 0, err
}

// ListRevoked returns the deny-list to install at boot and on refresh:
// UNEXPIRED revoked serials (expired certs refuse themselves) plus every
// revoked SPIFFE id (so a re-issued cert for a revoked identity is refused
// even past its predecessors' expiry).
func (a AgentIdentities) ListRevoked(ctx context.Context) (serials, spiffeIDs []string, err error) {
	rows, err := a.pool.Query(ctx,
		`SELECT serial, spiffe_id, not_after > now() AS live
		   FROM agent_identities WHERE revoked_at IS NOT NULL`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var s, sp string
		var live bool
		if err := rows.Scan(&s, &sp, &live); err != nil {
			return nil, nil, err
		}
		if live {
			serials = append(serials, s)
		}
		if !seen[sp] {
			seen[sp] = true
			spiffeIDs = append(spiffeIDs, sp)
		}
	}
	return serials, spiffeIDs, rows.Err()
}
