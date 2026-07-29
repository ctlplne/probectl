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

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
		_, err := sc.Q.Exec(ctx,
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
			 )`,
			tokenHash, sess.TenantID, sess.UserID, sess.Email, sess.DisplayName, sess.MFASatisfied,
			sess.TimeZone, sess.Locale, sess.TenantTimeZone, sess.TenantLocale, sess.ExpiresAt,
			sess.CreatedAt, sess.LastActivityAt, sess.AuthorizationHash)
		return err
	})
}

// LookupByHash atomically verifies absolute + idle expiry and touches activity.
// Returning no row deliberately conflates unknown, absolute-expired, and
// idle-expired tokens so the caller cannot use the endpoint as a session oracle.
func (s Sessions) LookupByHash(ctx context.Context, tokenHash []byte, idleTimeout time.Duration) (*auth.Session, error) {
	if idleTimeout <= 0 {
		idleTimeout = auth.DefaultSessionIdleTimeout
	}
	var sess auth.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, user_id::text, email, display_name, mfa_satisfied,
		        time_zone, locale, tenant_time_zone, tenant_locale, expires_at, created_at,
		        last_activity_at, authorization_hash
		   FROM pretenant_lookup_session($1, $2::interval)`,
		tokenHash, idleTimeout.String()).
		Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.Email, &sess.DisplayName,
			&sess.MFASatisfied, &sess.TimeZone, &sess.Locale, &sess.TenantTimeZone,
			&sess.TenantLocale, &sess.ExpiresAt, &sess.CreatedAt, &sess.LastActivityAt,
			&sess.AuthorizationHash)
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
	var rotated bool
	err := s.pool.QueryRow(ctx,
		`SELECT pretenant_rotate_session(
			$1, $2, $3::uuid, $4::uuid, $5
		 )`,
		oldHash, newHash, sess.TenantID, sess.UserID, sess.AuthorizationHash).
		Scan(&rotated)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return rotated, err
}

// ReplaceAuthenticatedByHash atomically consumes a browser's current (or
// pre-HMAC legacy) predecessor and inserts the session established by a fresh
// IdP authentication. All fields in sess are authoritative here; that is the
// deliberate inverse of permission-only RotateByHash.
//
// The database retains the predecessor as an inactive tombstone. That tiny bit
// of memory is what lets a concurrent loser distinguish "already consumed"
// from "unknown cookie" without a check-then-create race.
func (s Sessions) ReplaceAuthenticatedByHash(
	ctx context.Context,
	oldHash, legacyOldHash, newHash []byte,
	sess auth.Session,
) (bool, error) {
	sess = normalizeSessionTimes(sess)
	var created bool
	err := s.pool.QueryRow(ctx,
		`SELECT pretenant_replace_authenticated_session(
			$1, $2, $3,
			$4::uuid, $5::uuid, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14, $15, $16
		 )`,
		oldHash, legacyOldHash, newHash,
		sess.TenantID, sess.UserID, sess.Email, sess.DisplayName, sess.MFASatisfied,
		sess.TimeZone, sess.Locale, sess.TenantTimeZone, sess.TenantLocale,
		sess.ExpiresAt, sess.CreatedAt, sess.LastActivityAt, sess.AuthorizationHash).
		Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return created, err
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

// DeleteByHash revokes a session (logout).
func (s Sessions) DeleteByHash(ctx context.Context, tokenHash []byte) error {
	var deleted bool
	return s.pool.QueryRow(ctx, `SELECT pretenant_delete_session($1)`, tokenHash).Scan(&deleted)
}

// DeleteAllForUser revokes every active session of a user in a tenant — the
// immediate-revocation path on SCIM deprovision (S31). It is keyed by
// (tenant_id, user_id) so a deprovisioned user's next request fails session
// resolution at once. Returns the number of sessions removed.
func (s Sessions) DeleteAllForUser(ctx context.Context, tenantID, userID string) (int64, error) {
	var deleted int64
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		tag, err := sc.Q.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
		if err == nil {
			deleted = tag.RowsAffected()
		}
		return err
	})
	return deleted, err
}
