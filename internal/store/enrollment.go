// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Agent enrollment storage (Sprint 11; ADR docs/adr/agent-enrollment.md).
// The CONSUME path is PRE-TENANT because the token hash selects its tenant, but
// the narrow SECURITY DEFINER locator exposes only that tenant id; the detailed
// row is then consumed under tenancy.InTenant in the routed schema. Every direct
// table operation with a known tenant is RLS-scoped, and an application-role
// statement with no tenant GUC sees no rows.

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
	// tenant_id). The pre-tenant Consume path uses its hash-only locator and
	// then this same tenant-scoped table.
	var id string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx,
			`INSERT INTO agent_enroll_tokens (tenant_id, agent_id, name, token_hash, created_by, expires_at)
			 VALUES ($1, NULLIF($2,''), $3, $4, $5, now() + $6) RETURNING id::text`,
			tenantID, agentID, name, tokenHash, createdBy, ttl,
		).Scan(&id); err != nil {
			return err
		}
		return registerCredential(ctx, sc, credentialAgentEnroll, id, tokenHash)
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
	tenantID, err = resolveCredential(ctx, e.pool, credentialAgentEnroll, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrEnrollTokenInvalid
	}
	if err != nil {
		return "", "", err
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		e.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx,
				`UPDATE agent_enroll_tokens
				    SET used_at = now(), used_by_agent = $2
				  WHERE token_hash = $1
				    AND tenant_id = $3
				    AND used_at IS NULL
				    AND revoked_at IS NULL
				    AND expires_at > now()
				 RETURNING COALESCE(agent_id, '')`,
				tokenHash, usedByAgent, tenantID,
			).Scan(&pinnedAgentID); err != nil {
				return err
			}
			return consumeCredential(
				ctx, sc, credentialAgentEnroll, tokenHash,
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) ||
		errors.Is(err, errCredentialStateChanged) {
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
		if err := sc.Q.QueryRow(ctx,
			`UPDATE agent_enroll_tokens
			    SET used_at = now(), used_by_agent = $3
			  WHERE token_hash = $1
			    AND tenant_id = $2
			    AND used_at IS NULL
			    AND revoked_at IS NULL
			    AND expires_at > now()
			 RETURNING COALESCE(agent_id, '')`,
			tokenHash, tenantID, usedByAgent,
		).Scan(&pinnedAgentID); err != nil {
			return err
		}
		return consumeCredential(ctx, sc, credentialAgentEnroll, tokenHash)
	})
	if errors.Is(err, pgx.ErrNoRows) ||
		errors.Is(err, errCredentialStateChanged) {
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
	tenantID, err := resolveCredentialID(
		ctx, e.pool, credentialAgentEnroll, id,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var revoked bool
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		e.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var tokenHash []byte
			if err := sc.Q.QueryRow(ctx,
				`UPDATE agent_enroll_tokens
				    SET revoked_at = now()
				  WHERE id = $1::uuid
				    AND tenant_id = $2
				    AND used_at IS NULL
				    AND revoked_at IS NULL
				 RETURNING token_hash`,
				id, tenantID,
			).Scan(&tokenHash); err != nil {
				return err
			}
			if err := revokeCredential(
				ctx, sc, credentialAgentEnroll, tokenHash,
			); err != nil {
				return err
			}
			revoked = true
			return nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) ||
		errors.Is(err, errCredentialStateChanged) {
		return false, nil
	}
	return revoked, err
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

// AgentIdentityWindow is the lifetime of ONE issued SVID: when this deployment
// signed it and when it stops being an identity. It carries no key material and
// no serial — the fleet view needs the window, not the credential.
type AgentIdentityWindow struct {
	IssuedAt time.Time
	NotAfter time.Time
}

// LiveForAgents returns the newest non-revoked identity window per agent, for
// agents already selected inside the caller's RLS transaction.
//
// DPR-176: the fleet view knew when an agent last spoke and what version it
// ran, and nothing at all about the certificate that lets it speak. Rotation
// failing is the one fault that kills an agent silently — it keeps working on
// the identity it holds, then stops for good — so the window behind it belongs
// in the same view as the heartbeat.
func (AgentIdentities) LiveForAgents(ctx context.Context, s tenancy.Scope, agentIDs []string) (map[string]AgentIdentityWindow, error) {
	out := make(map[string]AgentIdentityWindow, len(agentIDs))
	if len(agentIDs) == 0 {
		return out, nil
	}
	rows, err := s.Q.Query(ctx, `
		SELECT DISTINCT ON (agent_id) agent_id, issued_at, not_after
		  FROM agent_identities
		 WHERE agent_id = ANY($1::text[]) AND revoked_at IS NULL
		 ORDER BY agent_id, not_after DESC, issued_at DESC`, agentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var w AgentIdentityWindow
		if err := rows.Scan(&id, &w.IssuedAt, &w.NotAfter); err != nil {
			return nil, err
		}
		out[id] = w
	}
	return out, rows.Err()
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

// KnownIssuedIdentity reports whether the exact tenant, registry id, SPIFFE
// plane identity, and certificate serial were issued by this deployment. The
// BMP listener uses this after deriving the tenant from the verified
// certificate; InTenant makes a tenant-A credential unobservable in tenant B
// even if a caller supplies mismatched application fields.
func (a AgentIdentities) KnownIssuedIdentity(ctx context.Context, tenantID, agentID, spiffeID, serial string) (bool, error) {
	var n int
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx,
			`SELECT count(*)
			   FROM agent_identities
			  WHERE tenant_id = $1
			    AND agent_id = $2
			    AND spiffe_id = $3
			    AND serial = $4`,
			tenantID, agentID, spiffeID, serial).Scan(&n)
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
// The operator supplies the tenant explicitly (including from the CLI), so the
// whole revocation remains inside that tenant's RLS transaction.
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
			`SELECT serial, spiffe_id, not_after, revoked_at, revoked_by
			   FROM agent_identities
			  WHERE tenant_id = $1 AND agent_id = $2 AND revoked_at IS NOT NULL`,
			tenantID, agentID)
		if err != nil {
			return err
		}
		type revokedIdentity struct {
			serial, spiffe, revokedBy string
			notAfter, revokedAt       time.Time
		}
		var revoked []revokedIdentity
		for rows.Next() {
			var item revokedIdentity
			if err := rows.Scan(
				&item.serial, &item.spiffe, &item.notAfter,
				&item.revokedAt, &item.revokedBy,
			); err != nil {
				rows.Close()
				return err
			}
			revoked = append(revoked, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(revoked) == 0 {
			return apierror.NotFound("agent has no issued identities").
				Wrap(fmt.Errorf("store: agent %s has no issued identities in tenant %s", agentID, tenantID))
		}
		for _, item := range revoked {
			var synced bool
			if err := sc.Q.QueryRow(ctx,
				`SELECT pretenant_sync_agent_revocation(
					$1::uuid, $2, $3, $4, $5, $6, $7
				 )`,
				tenantID, agentID, item.spiffe, item.serial,
				item.notAfter, item.revokedAt, item.revokedBy,
			).Scan(&synced); err != nil {
				return err
			}
			if !synced {
				return tenancy.ErrNoTenant
			}
			spiffeID = item.spiffe
			if item.notAfter.After(time.Now()) {
				serials = append(serials, item.serial)
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
	err = tenancy.InProvider(ctx, a.pool, func(ctx context.Context, q tenancy.Querier) error {
		var listErr error
		serials, spiffeIDs, listErr = listRevoked(ctx, q)
		return listErr
	})
	return serials, spiffeIDs, err
}

// BMPRevocationReaderRole is the NOLOGIN execute-only role that the standalone
// BMP listener assumes while reading the cross-tenant revocation snapshot.
const BMPRevocationReaderRole = "probectl_bmp_revocation_reader"

// BMPRevocations exposes only the signed-off revocation snapshot function. It
// never reads tenant tables directly; SET LOCAL ROLE makes the database enforce
// the execute-only boundary even when the connection login has broader rights.
type BMPRevocations struct{ pool *pgxpool.Pool }

// NewBMPRevocations binds the standalone-listener snapshot reader to its pool.
func NewBMPRevocations(pool *pgxpool.Pool) BMPRevocations {
	return BMPRevocations{pool: pool}
}

// List returns a complete authoritative snapshot under the dedicated NOLOGIN
// role. The caller replaces its in-memory list only after this method succeeds.
func (r BMPRevocations) List(ctx context.Context) (serials, spiffeIDs []string, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin BMP revocation snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(
		ctx,
		"SET LOCAL ROLE "+pgx.Identifier{BMPRevocationReaderRole}.Sanitize(),
	); err != nil {
		return nil, nil, fmt.Errorf("assume BMP revocation reader role: %w", err)
	}
	serials, spiffeIDs, err = listRevoked(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit BMP revocation snapshot: %w", err)
	}
	return serials, spiffeIDs, nil
}

func listRevoked(ctx context.Context, q tenancy.Querier) (serials, spiffeIDs []string, err error) {
	rows, err := q.Query(ctx,
		`SELECT serial, spiffe_id, live
		   FROM provider_list_revoked_agent_identities()`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var serial, spiffeID string
		var live bool
		if err := rows.Scan(&serial, &spiffeID, &live); err != nil {
			return nil, nil, err
		}
		if live {
			serials = append(serials, serial)
		}
		if !seen[spiffeID] {
			seen[spiffeID] = true
			spiffeIDs = append(spiffeIDs, spiffeID)
		}
	}
	return serials, spiffeIDs, rows.Err()
}
