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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrWorkerCredentialUnavailable = errors.New("store: originating worker credential state is unavailable")

// WorkerCredentials verifies an already tenant/owner-bound origin reference.
// It does NOT authenticate requests or return grants. The control service must
// separately load current grants/scopes/attributes/MFA/lifecycle and authorize
// each source, context and publication. These reads never touch activity.
type WorkerCredentials struct {
	pool *pgxpool.Pool
	idle time.Duration
}

func NewWorkerCredentials(pool *pgxpool.Pool, idle time.Duration) (WorkerCredentials, error) {
	if idle == 0 {
		idle = auth.DefaultSessionIdleTimeout
	}
	if pool == nil || idle < 0 {
		return WorkerCredentials{}, ErrWorkerCredentialUnavailable
	}
	return WorkerCredentials{pool: pool, idle: idle}, nil
}

func (w WorkerCredentials) scopedID(ctx context.Context, tenant, owner string, ref auth.WorkerCredentialRef, wanted auth.WorkerCredentialKind) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ambient, ok := tenancy.FromContext(ctx)
	if !ok || ambient.String() != tenant {
		return "", auth.ErrWorkerCredentialInvalid
	}
	kind, id, err := ref.ScopedID(tenant, owner)
	if err != nil || kind != wanted {
		return "", auth.ErrWorkerCredentialInvalid
	}
	if w.pool == nil || w.idle <= 0 {
		return "", ErrWorkerCredentialUnavailable
	}
	return id, nil
}

// RevalidateSession returns only the current live session metadata. Replaced,
// rotated, expired, idle-expired, deleted and inactive-user origins fail closed.
// In particular it never calls LookupByHash or updates last_activity_at.
func (w WorkerCredentials) RevalidateSession(ctx context.Context, tenant, owner string, ref auth.WorkerCredentialRef) (*auth.Session, error) {
	id, err := w.scopedID(ctx, tenant, owner, ref, auth.WorkerCredentialSession)
	if err != nil {
		return nil, err
	}
	var session auth.Session
	err = tenancy.InTenant(ctx, w.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var storedHash []byte
		if err := sc.Q.QueryRow(ctx, `
		 SELECT s.id::text, s.tenant_id::text, s.user_id::text,
		        s.email, s.display_name, s.mfa_satisfied, s.time_zone, s.locale,
		        s.tenant_time_zone, s.tenant_locale, s.expires_at, s.created_at,
		        s.last_activity_at, s.authorization_hash, s.token_hash
		   FROM sessions s
		   JOIN users u ON u.tenant_id = s.tenant_id AND u.id = s.user_id
		  WHERE s.tenant_id = $1 AND s.user_id = $2 AND s.id = $3
		    AND u.status = 'active' AND s.replaced_at IS NULL
		    AND s.expires_at > now()
		    AND s.last_activity_at > now() - $4::interval`,
			tenant, owner, id, w.idle.String(),
		).Scan(&session.ID, &session.TenantID, &session.UserID,
			&session.Email, &session.DisplayName, &session.MFASatisfied, &session.TimeZone, &session.Locale,
			&session.TenantTimeZone, &session.TenantLocale, &session.ExpiresAt, &session.CreatedAt,
			&session.LastActivityAt, &session.AuthorizationHash, &storedHash); err != nil {
			return err
		}
		if !ref.MatchesStored(auth.WorkerCredentialSession, session.TenantID, session.UserID, session.ID, storedHash) {
			return auth.ErrWorkerCredentialInvalid
		}
		return nil
	})
	if err := workerCredentialReadError(ctx, err); err != nil {
		return nil, err
	}
	return &session, nil
}

// RevalidateMCP returns current credential scopes, never cached owner grants.
// It does not stamp last_used_at or produce a first-use authentication event.
func (w WorkerCredentials) RevalidateMCP(ctx context.Context, tenant, owner string, ref auth.WorkerCredentialRef) (AuthResult, error) {
	id, err := w.scopedID(ctx, tenant, owner, ref, auth.WorkerCredentialMCP)
	if err != nil {
		return AuthResult{}, err
	}
	var result AuthResult
	err = tenancy.InTenant(ctx, w.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var storedHash []byte
		if err := sc.Q.QueryRow(ctx, `
		 SELECT t.id::text, t.tenant_id::text, t.user_id::text, t.scopes, t.token_hash
		   FROM mcp_tokens t
		   JOIN users u ON u.tenant_id = t.tenant_id AND u.id = t.user_id
		  WHERE t.tenant_id = $1 AND t.user_id = $2 AND t.id = $3
		    AND u.status = 'active' AND t.revoked_at IS NULL
		    AND (t.expires_at IS NULL OR t.expires_at > now())`, tenant, owner, id,
		).Scan(&result.TokenID, &result.TenantID, &result.UserID, &result.Scopes, &storedHash); err != nil {
			return err
		}
		if !ref.MatchesStored(auth.WorkerCredentialMCP, result.TenantID, result.UserID, result.TokenID, storedHash) {
			return auth.ErrWorkerCredentialInvalid
		}
		return nil
	})
	if err := workerCredentialReadError(ctx, err); err != nil {
		return AuthResult{}, err
	}
	result.Scopes = append([]string{}, result.Scopes...)
	return result, nil
}

func workerCredentialReadError(ctx context.Context, err error) error {
	if callerErr := ctx.Err(); callerErr != nil {
		return callerErr
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, auth.ErrWorkerCredentialInvalid) {
		return auth.ErrWorkerCredentialInvalid
	}
	if err != nil {
		return ErrWorkerCredentialUnavailable
	}
	return nil
}
