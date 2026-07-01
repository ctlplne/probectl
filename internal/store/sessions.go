// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"errors"

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
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (
			token_hash, tenant_id, user_id, email, display_name, mfa_satisfied,
			time_zone, locale, tenant_time_zone, tenant_locale, expires_at
		 )
		 VALUES (
			$1, $2, $3, $4, $5, $6,
			COALESCE(NULLIF($7, ''), 'UTC'), COALESCE(NULLIF($8, ''), 'en'),
			COALESCE(NULLIF($9, ''), 'UTC'), COALESCE(NULLIF($10, ''), 'en'),
			$11
		 )`,
		tokenHash, sess.TenantID, sess.UserID, sess.Email, sess.DisplayName, sess.MFASatisfied,
		sess.TimeZone, sess.Locale, sess.TenantTimeZone, sess.TenantLocale, sess.ExpiresAt)
	return err
}

// LookupByHash returns the non-expired session for a token hash, or (nil, nil)
// when none matches (unknown or expired token — fail closed, no leak of why).
func (s Sessions) LookupByHash(ctx context.Context, tokenHash []byte) (*auth.Session, error) {
	var sess auth.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, user_id::text, email, display_name, mfa_satisfied,
		        time_zone, locale, tenant_time_zone, tenant_locale, expires_at, created_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHash).
		Scan(&sess.ID, &sess.TenantID, &sess.UserID, &sess.Email, &sess.DisplayName,
			&sess.MFASatisfied, &sess.TimeZone, &sess.Locale, &sess.TenantTimeZone,
			&sess.TenantLocale, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
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
