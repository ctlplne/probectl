// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// TokenStore is the persistence interface for DB-backed OTLP tokens
// (WIRE-008). Implemented by store.OTLPTokens; the interface lets the DB layer
// be tested independently from the in-process cache.
type TokenStore interface {
	// Authenticate resolves a token hash to its tenant, stamping last_used_at.
	// Returns ("", ErrInvalidOTLPToken) for an unknown or revoked token.
	Authenticate(ctx context.Context, tokenHash []byte) (tenantID string, err error)
}

// DBTokenAuthenticator is an Authenticator that resolves OTLP bearer tokens
// against a persistence layer (WIRE-008). It also holds the in-process
// TokenAuthenticator so config-seeded tokens still work; the DB layer is the
// authoritative source for admin-issued and recently-revoked tokens.
//
// The hot-revocation contract: calling Revoke on the DB store marks the token
// revoked. Subsequent Authenticate calls hit the DB and get ErrInvalidOTLPToken
// immediately (no restart required). The in-process cache is ALSO updated so
// the next request does not make a spurious DB round-trip.
type DBTokenAuthenticator struct {
	db  TokenStore // DB-backed source of truth
	mem *TokenAuthenticator
	log *slog.Logger
}

// NewDBTokenAuthenticator builds an authenticator that accepts legacy
// config-seeded tokens and DB-issued tokens. DB-issued tokens are persisted and
// hot-revocable; config-seeded tokens remain controlled by config+restart. The
// first successful DB-issued token lookup seeds the in-memory layer, but each
// later hit re-checks the DB so revocation takes effect without restart.
func NewDBTokenAuthenticator(db TokenStore, configTokens map[string]string, log *slog.Logger) *DBTokenAuthenticator {
	if log == nil {
		log = slog.Default()
	}
	return &DBTokenAuthenticator{
		db:  db,
		mem: NewTokenAuthenticator(configTokens),
		log: log,
	}
}

// Authenticate resolves a bearer token to a tenant. Config-seeded tokens are
// accepted from the in-process authenticator. DB-issued tokens are checked
// against the DB on every hit so revocation takes effect without restart.
func (a *DBTokenAuthenticator) Authenticate(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrUnauthenticated
	}

	// Fast path: check the in-process cache.
	if tenant, source, err := a.mem.authenticateEntry(token); err == nil {
		if source == tokenSourceConfig {
			return tenant, nil
		}
		// DB-issued token: verify the DB row is still live. If someone revoked
		// it via the admin API, the DB returns ErrInvalidOTLPToken immediately.
		dbTenant, dbErr := a.db.Authenticate(ctx, crypto.Hash([]byte(token)))
		if dbErr != nil {
			// Token was revoked in DB — evict from in-process cache immediately.
			a.mem.Revoke(token)
			a.log.Warn("otlp token revoked (DB hot-revocation)", "tenant", tenant)
			return "", ErrUnauthenticated
		}
		// DB is authoritative for the tenant binding; prefer its value.
		_ = tenant
		return dbTenant, nil
	}

	// Slow path: not in in-process cache — try the DB (admin-issued token).
	dbTenant, dbErr := a.db.Authenticate(ctx, crypto.Hash([]byte(token)))
	if dbErr != nil {
		return "", ErrUnauthenticated
	}
	// Seed into the in-process cache so the next call takes the fast path.
	a.mem.Add(token, dbTenant, time.Time{})
	return dbTenant, nil
}

// Add registers an additional valid token (rotation). Callers (the admin API
// handler) must ALSO persist the token via the DB store before calling Add so
// the in-process layer and the DB are consistent.
func (a *DBTokenAuthenticator) Add(token, tenant string, expires time.Time) {
	a.mem.Add(token, tenant, expires)
}

// Revoke marks a token revoked in the in-process cache. The admin API handler
// must ALSO call store.OTLPTokens.Revoke to persist the revocation.
func (a *DBTokenAuthenticator) Revoke(token string) bool {
	return a.mem.Revoke(token)
}

// ActiveTokens counts currently-valid in-process tokens (for diagnostics).
func (a *DBTokenAuthenticator) ActiveTokens() int {
	return a.mem.ActiveTokens()
}
