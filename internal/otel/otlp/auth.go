// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// ErrUnauthenticated is returned by an Authenticator for a missing/invalid token.
var ErrUnauthenticated = errors.New("otlp: unauthenticated")

// Authenticator resolves an OTLP bearer token to the tenant it is scoped to.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (tenant string, err error)
}

// tokenEntry holds the SHA-256 of a bearer secret (never the plaintext after
// construction), its tenant, and rotation state.
type tokenEntry struct {
	hash    []byte // crypto.Hash(secret) — fixed 32 bytes for constant-time compare
	tenant  string
	expires time.Time // zero = never
	revoked bool
	source  tokenSource
}

type tokenSource string

const (
	tokenSourceConfig tokenSource = "config"
	tokenSourceDB     tokenSource = "db"
)

func (e tokenEntry) live(now time.Time) bool {
	return !e.revoked && (e.expires.IsZero() || now.Before(e.expires))
}

// TokenAuthenticator resolves OTLP bearer tokens to tenants (PROBECTL_OTLP_TOKENS).
// Comparison is CONSTANT-TIME over a hash of the token (U-076), and the set
// supports rotation — multiple concurrently-valid tokens, optional per-token
// expiry, and revocation (U-077). Tokens are bearer secrets carried over TLS;
// production may additionally use mTLS / SPIFFE identity.
type TokenAuthenticator struct {
	mu      sync.RWMutex
	entries []tokenEntry
	now     func() time.Time
}

// NewTokenAuthenticator builds an authenticator from token→tenant pairs (empty
// keys/values dropped). Config-loaded tokens have no expiry; rotate by Add-ing
// a new token then Revoke-ing the old.
func NewTokenAuthenticator(tokenToTenant map[string]string) *TokenAuthenticator {
	a := &TokenAuthenticator{now: time.Now}
	for tok, tenant := range tokenToTenant {
		if tok != "" && tenant != "" {
			a.entries = append(a.entries, tokenEntry{hash: crypto.Hash([]byte(tok)), tenant: tenant, source: tokenSourceConfig})
		}
	}
	return a
}

// Add registers an additional valid token (rotation): both old and new are
// accepted until the old is revoked. expires of zero means no expiry.
func (a *TokenAuthenticator) Add(token, tenant string, expires time.Time) {
	a.add(token, tenant, expires, tokenSourceDB)
}

func (a *TokenAuthenticator) add(token, tenant string, expires time.Time, source tokenSource) {
	if token == "" || tenant == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, tokenEntry{hash: crypto.Hash([]byte(token)), tenant: tenant, expires: expires, source: source})
}

// Revoke marks every entry for token as revoked (immediate). Returns whether
// any matched. This is the in-process revocation path; the env-config path is
// to drop the token from PROBECTL_OTLP_TOKENS and reload (docs/otlp.md).
func (a *TokenAuthenticator) Revoke(token string) bool {
	if token == "" {
		return false
	}
	h := crypto.Hash([]byte(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	revoked := false
	for i := range a.entries {
		if crypto.ConstantTimeEqual(h, a.entries[i].hash) {
			a.entries[i].revoked = true
			revoked = true
		}
	}
	return revoked
}

// ActiveTokens counts currently-valid (unexpired, unrevoked) tokens — for the
// operator's rotation visibility (surfaced via diagnostics).
func (a *TokenAuthenticator) ActiveTokens() int {
	now := a.now()
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := 0
	for _, e := range a.entries {
		if e.live(now) {
			n++
		}
	}
	return n
}

// Authenticate resolves a token to its tenant, failing closed. The secret
// comparison is constant-time and checks EVERY entry (no early exit), so
// neither match position nor a near-miss leaks through timing.
func (a *TokenAuthenticator) Authenticate(_ context.Context, token string) (string, error) {
	tenant, _, err := a.authenticateEntry(token)
	return tenant, err
}

func (a *TokenAuthenticator) authenticateEntry(token string) (string, tokenSource, error) {
	if token == "" {
		return "", "", ErrUnauthenticated
	}
	h := crypto.Hash([]byte(token))
	now := a.now()
	a.mu.RLock()
	defer a.mu.RUnlock()
	tenant := ""
	source := tokenSource("")
	matched := 0
	for _, e := range a.entries {
		// Constant-time secret compare on EVERY entry (no early exit), so
		// neither match position nor a near-miss leaks through timing.
		if crypto.ConstantTimeEqual(h, e.hash) && e.live(now) {
			tenant = e.tenant
			source = e.source
			matched = 1
		}
	}
	if matched == 1 {
		return tenant, source, nil
	}
	return "", "", ErrUnauthenticated
}

type tenantKey struct{}

func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tenantKey{}).(string)
	return t, ok && t != ""
}

// authUnaryInterceptor authenticates each RPC's bearer token and puts the
// resolved tenant on the context; it fails closed with Unauthenticated.
func authUnaryInterceptor(auth Authenticator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		tenant, err := auth.Authenticate(ctx, bearerFromMetadata(ctx))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "otlp: invalid or missing bearer token")
		}
		return handler(withTenant(ctx, tenant), req)
	}
}

func bearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	return bearerFromHeader(vals[0])
}

func bearerFromHeader(authz string) string {
	return strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
}
