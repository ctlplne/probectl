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
)

// Sessions is the server-side session store. Sessions are GLOBAL (looked up by
// token hash before any tenant context exists), so this repo uses the pool
// directly rather than a tenant-scoped transaction; it implements
// auth.SessionStore.
type Sessions struct {
	pool *pgxpool.Pool
}

// NewSessions builds the session store over the connection pool.
func NewSessions(pool *pgxpool.Pool) Sessions { return Sessions{pool: pool} }

// Create stores a session keyed by the hash of its opaque token.
func (s Sessions) Create(ctx context.Context, tokenHash []byte, sess auth.Session) error {
	sess = normalizeSessionTimes(sess)
	_, err := s.pool.Exec(ctx,
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
		`UPDATE sessions
		 SET last_activity_at = now()
		 WHERE token_hash = $1
		   AND expires_at > now()
		   AND last_activity_at > now() - $2::interval
		 RETURNING id::text, tenant_id::text, user_id::text, email, display_name, mfa_satisfied,
		           time_zone, locale, tenant_time_zone, tenant_locale, expires_at, created_at,
		           last_activity_at, authorization_hash`, tokenHash, idleTimeout.String()).
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

// RotateByHash atomically consumes oldHash and inserts its single successor.
// If two requests race after an authorization change, only one DELETE can
// return a row, so only one replacement token becomes valid.
func (s Sessions) RotateByHash(ctx context.Context, oldHash, newHash []byte, sess auth.Session) (bool, error) {
	sess = normalizeSessionTimes(sess)
	var rotated bool
	err := s.pool.QueryRow(ctx,
		`WITH removed AS (
			DELETE FROM sessions WHERE token_hash = $1 RETURNING 1
		 )
		 INSERT INTO sessions (
			token_hash, tenant_id, user_id, email, display_name, mfa_satisfied,
			time_zone, locale, tenant_time_zone, tenant_locale, expires_at,
			created_at, last_activity_at, authorization_hash
		 )
		 SELECT $2, $3, $4, $5, $6, $7,
		        COALESCE(NULLIF($8, ''), 'UTC'), COALESCE(NULLIF($9, ''), 'en'),
		        COALESCE(NULLIF($10, ''), 'UTC'), COALESCE(NULLIF($11, ''), 'en'),
		        $12, $13, $14, COALESCE($15, '\x'::bytea)
		 FROM removed
		 RETURNING true`,
		oldHash, newHash, sess.TenantID, sess.UserID, sess.Email, sess.DisplayName,
		sess.MFASatisfied, sess.TimeZone, sess.Locale, sess.TenantTimeZone,
		sess.TenantLocale, sess.ExpiresAt, sess.CreatedAt, sess.LastActivityAt,
		sess.AuthorizationHash).Scan(&rotated)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return rotated, err
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
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteAllForUser revokes every active session of a user in a tenant — the
// immediate-revocation path on SCIM deprovision (S31). It is keyed by
// (tenant_id, user_id) so a deprovisioned user's next request fails session
// resolution at once. Returns the number of sessions removed.
func (s Sessions) DeleteAllForUser(ctx context.Context, tenantID, userID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return tag.RowsAffected(), err
}
