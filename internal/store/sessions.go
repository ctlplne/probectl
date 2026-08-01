// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Sessions is the server-side session store. Direct table access is always
// tenant-scoped. The few operations that must resolve an opaque hash before the
// tenant is known use narrow pretenant_* database functions; it implements
// auth.SessionStore.
type Sessions struct {
	pool *pgxpool.Pool
}

// NewSessions builds the session store over the connection pool.
func NewSessions(pool *pgxpool.Pool) Sessions { return Sessions{pool: pool} }

// Create stores a session keyed by the hash of its opaque token.
func (s Sessions) Create(ctx context.Context, tokenHash []byte, sess auth.Session) error {
	sess = normalizeSessionTimes(sess)
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(sess.TenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var id string
		if err := sc.Q.QueryRow(ctx,
			`INSERT INTO sessions (
				token_hash, tenant_id, user_id, email, display_name, mfa_satisfied,
				time_zone, locale, tenant_time_zone, tenant_locale, expires_at,
				created_at, last_activity_at, authorization_hash
			 )
			 VALUES (
				$1, $2, $3, $4, $5, $6,
				COALESCE(NULLIF($7, ''), 'UTC'), COALESCE(NULLIF($8, ''), 'en'),
				COALESCE(NULLIF($9, ''), 'UTC'), COALESCE(NULLIF($10, ''), 'en'),
				$11, $12, $13, COALESCE($14, '\x'::bytea)
			 )
			 RETURNING id::text`,
			tokenHash, sess.TenantID, sess.UserID, sess.Email, sess.DisplayName, sess.MFASatisfied,
			sess.TimeZone, sess.Locale, sess.TenantTimeZone, sess.TenantLocale, sess.ExpiresAt,
			sess.CreatedAt, sess.LastActivityAt, sess.AuthorizationHash,
		).Scan(&id); err != nil {
			return err
		}
		return registerCredential(ctx, sc, credentialSession, id, tokenHash)
	})
}

// LookupByHash atomically verifies absolute + idle expiry and touches activity.
// Returning no row deliberately conflates unknown, absolute-expired, and
// idle-expired tokens so the caller cannot use the endpoint as a session oracle.
func (s Sessions) LookupByHash(ctx context.Context, tokenHash []byte, idleTimeout time.Duration) (*auth.Session, error) {
	if idleTimeout <= 0 {
		idleTimeout = auth.DefaultSessionIdleTimeout
	}
	tenantID, err := resolveCredential(ctx, s.pool, credentialSession, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess auth.Session
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx,
				`UPDATE sessions
				    SET last_activity_at = now()
				  WHERE token_hash = $1
				    AND tenant_id = $2
				    AND replaced_at IS NULL
				    AND expires_at > now()
				    AND last_activity_at > now() - $3::interval
				 RETURNING id::text, tenant_id::text, user_id::text, email,
				           display_name, mfa_satisfied, time_zone, locale,
				           tenant_time_zone, tenant_locale, expires_at,
				           created_at, last_activity_at, authorization_hash`,
				tokenHash, tenantID, idleTimeout.String(),
			).Scan(
				&sess.ID, &sess.TenantID, &sess.UserID, &sess.Email,
				&sess.DisplayName, &sess.MFASatisfied, &sess.TimeZone,
				&sess.Locale, &sess.TenantTimeZone, &sess.TenantLocale,
				&sess.ExpiresAt, &sess.CreatedAt, &sess.LastActivityAt,
				&sess.AuthorizationHash,
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// RotateByHash atomically replaces oldHash with its single successor. The
// database copies no caller-controlled identity, MFA, preference, or lifetime
// fields: it updates only the token hash, activity time, and authorization
// fingerprint on the authoritative source row.
func (s Sessions) RotateByHash(ctx context.Context, oldHash, newHash []byte, sess auth.Session) (bool, error) {
	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(sess.TenantID)),
		s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			tag, err := sc.Q.Exec(ctx,
				`UPDATE sessions
				    SET token_hash = $2,
				        last_activity_at = now(),
				        authorization_hash = COALESCE($5, '\x'::bytea)
				  WHERE token_hash = $1
				    AND replaced_at IS NULL
				    AND tenant_id = $3
				    AND user_id = $4`,
				oldHash, newHash, sess.TenantID, sess.UserID,
				sess.AuthorizationHash,
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errCredentialStateChanged
			}
			return rotateCredential(ctx, sc, credentialSession, oldHash, newHash)
		},
	)
	if errors.Is(err, errCredentialStateChanged) {
		return false, nil
	}
	return err == nil, err
}

// ReplaceAuthenticatedByHash atomically consumes a browser's current (or
// pre-HMAC legacy) predecessor and inserts the session established by a fresh
// IdP authentication. All fields in sess are authoritative here; that is the
// deliberate inverse of permission-only RotateByHash.
//
// The database retains the predecessor's hash-only locator as an inactive
// tombstone. That tiny bit of global metadata lets a concurrent loser
// distinguish "already consumed" from "unknown cookie" without moving the old
// session's detailed identity out of its tenant silo.
func (s Sessions) ReplaceAuthenticatedByHash(
	ctx context.Context,
	oldHash, legacyOldHash, newHash []byte,
	sess auth.Session,
) (bool, error) {
	sess = normalizeSessionTimes(sess)
	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(sess.TenantID)),
		s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var id string
			if err := sc.Q.QueryRow(ctx,
				`INSERT INTO sessions (
					token_hash, tenant_id, user_id, email, display_name,
					mfa_satisfied, time_zone, locale, tenant_time_zone,
					tenant_locale, expires_at, created_at, last_activity_at,
					authorization_hash
				 )
				 VALUES (
					$1, $2, $3, $4, $5, $6,
					COALESCE(NULLIF($7, ''), 'UTC'),
					COALESCE(NULLIF($8, ''), 'en'),
					COALESCE(NULLIF($9, ''), 'UTC'),
					COALESCE(NULLIF($10, ''), 'en'),
					$11, $12, $13, COALESCE($14, '\x'::bytea)
				 )
				 RETURNING id::text`,
				newHash, sess.TenantID, sess.UserID, sess.Email,
				sess.DisplayName, sess.MFASatisfied, sess.TimeZone,
				sess.Locale, sess.TenantTimeZone, sess.TenantLocale,
				sess.ExpiresAt, sess.CreatedAt, sess.LastActivityAt,
				sess.AuthorizationHash,
			).Scan(&id); err != nil {
				return err
			}

			var created bool
			if err := sc.Q.QueryRow(ctx,
				`SELECT pretenant_replace_session_locator(
					$1, $2, $3::uuid, $4, $5::uuid
				 )`,
				oldHash, legacyOldHash, id, newHash, sess.TenantID,
			).Scan(&created); err != nil {
				return err
			}
			if !created {
				return errCredentialStateChanged
			}

			// When the predecessor belongs to this same tenant, retain the
			// detailed-row marker too. A cross-tenant predecessor stays private
			// in its original silo; its shared locator is the authoritative
			// inactive tombstone.
			_, err := sc.Q.Exec(ctx,
				`UPDATE sessions
				    SET replaced_at = COALESCE(replaced_at, now())
				  WHERE token_hash = $1
				     OR ($2::bytea IS NOT NULL AND token_hash = $2)`,
				oldHash, legacyOldHash,
			)
			return err
		},
	)
	if errors.Is(err, errCredentialStateChanged) {
		return false, nil
	}
	return err == nil, err
}

func normalizeSessionTimes(sess auth.Session) auth.Session {
	now := time.Now()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastActivityAt.IsZero() {
		sess.LastActivityAt = sess.CreatedAt
	}
	return sess
}

// PruneInactive removes tenant-owned session detail that can no longer
// authenticate: absolutely-expired rows immediately, and consumed predecessor
// detail after one replay-protection horizon. The global credential_locators
// rows are deliberately untouched. Their hash-only tombstones remain the
// cross-silo lock that prevents cleanup racing with authenticated callbacks
// from minting multiple successors.
//
// replayHorizon is derived from the configured session TTL by the caller. A
// non-positive value uses the same safe default as auth.Manager.
func (s Sessions) PruneInactive(
	ctx context.Context,
	tenantID string,
	replayHorizon time.Duration,
) (int64, error) {
	if replayHorizon <= 0 {
		replayHorizon = auth.DefaultSessionTTL
	}
	var deleted int64
	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			expired, err := sc.Q.Exec(ctx,
				`DELETE FROM sessions
				  WHERE tenant_id = $1
				    AND expires_at <= now()`,
				tenantID,
			)
			if err != nil {
				return err
			}
			replaced, err := sc.Q.Exec(ctx,
				`DELETE FROM sessions
				  WHERE tenant_id = $1
				    AND replaced_at IS NOT NULL
				    AND replaced_at <= now() - $2::interval`,
				tenantID, replayHorizon.String(),
			)
			if err != nil {
				return err
			}
			deleted = expired.RowsAffected() + replaced.RowsAffected()
			return nil
		},
	)
	return deleted, err
}

// DeleteByHash revokes a session (logout).
func (s Sessions) DeleteByHash(ctx context.Context, tokenHash []byte) error {
	tenantID, err := resolveCredential(ctx, s.pool, credentialSession, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx,
				`DELETE FROM sessions
				  WHERE token_hash = $1
				    AND tenant_id = $2
				    AND replaced_at IS NULL`,
				tokenHash, tenantID,
			); err != nil {
				return err
			}
			return revokeCredential(ctx, sc, credentialSession, tokenHash)
		},
	)
	if errors.Is(err, errCredentialStateChanged) {
		return nil
	}
	return err
}

// DeleteAllForUser revokes every active session of a user in a tenant — the
// immediate-revocation path on SCIM deprovision (S31). It is keyed by
// (tenant_id, user_id) so a deprovisioned user's next request fails session
// resolution at once. Returns the number of sessions removed.
func (s Sessions) DeleteAllForUser(ctx context.Context, tenantID, userID string) (int64, error) {
	var deleted int64
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx,
			`DELETE FROM sessions
			  WHERE tenant_id = $1 AND user_id = $2
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
		deleted = int64(len(hashes))
		for _, hash := range hashes {
			if err := revokeCredential(ctx, sc, credentialSession, hash); err != nil {
				return err
			}
		}
		return nil
	})
	return deleted, err
}
