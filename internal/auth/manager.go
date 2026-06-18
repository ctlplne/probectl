// SPDX-License-Identifier: LicenseRef-probectl-TBD

package auth

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// SessionCookie is the name of the session cookie.
const SessionCookie = "probectl_session"

// Manager issues, resolves, and revokes sessions, and manages the session cookie.
type Manager struct {
	store   SessionStore
	ttl     time.Duration
	secure  bool
	hmacKey []byte // HMAC-SHA256 key for token hashing (KEYS-002); must be 32 bytes
}

// NewManager builds a session manager. secure controls the cookie's Secure flag
// (true in production behind HTTPS; false only for plain-HTTP dev/test).
// hmacKey must be 32 bytes (PROBECTL_SESSION_HMAC_KEY). Pass nil only in tests
// and explicit dev paths; production session auth supplies a key.
func NewManager(store SessionStore, ttl time.Duration, secure bool, hmacKey []byte) *Manager {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Manager{store: store, ttl: ttl, secure: secure, hmacKey: hmacKey}
}

// Issue mints a session for an authenticated user and returns the opaque token.
// Only the token's hash is stored, so a database read cannot recover it.
func (m *Manager) Issue(ctx context.Context, sess Session) (string, error) {
	raw, err := crypto.Random(32)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := time.Now()
	sess.CreatedAt = now
	sess.ExpiresAt = now.Add(m.ttl)
	if err := m.store.Create(ctx, m.hashToken(token), sess); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve returns the session for a token, or (nil, nil) if there is none/expired.
func (m *Manager) Resolve(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	sess, err := m.store.LookupByHash(ctx, m.hashToken(token))
	if err != nil || sess != nil || !m.keyedHashing() {
		return sess, err
	}
	// KEYS-002 migration window: sessions minted before the keyed hash rolled
	// out are stored under the legacy unkeyed digest. They expire naturally by
	// TTL; new sessions are always stored under the keyed digest.
	return m.store.LookupByHash(ctx, legacyHashToken(token))
}

// Revoke deletes a session (logout).
func (m *Manager) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if err := m.store.DeleteByHash(ctx, m.hashToken(token)); err != nil {
		return err
	}
	if m.keyedHashing() {
		return m.store.DeleteByHash(ctx, legacyHashToken(token))
	}
	return nil
}

// SetCookie writes the session cookie: Secure (in prod) + HttpOnly + SameSite=Lax.
func (m *Manager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(m.ttl),
	})
}

// ClearCookie expires the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// TokenFromRequest reads the session token from the request cookie.
func TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// hashToken hashes the token through internal/crypto (FIPS-swappable; the token
// is the secret and is never stored in the clear). When the manager carries a
// 32-byte HMAC key (PROBECTL_SESSION_HMAC_KEY), the hash is HMAC-SHA256 keyed
// under that key - a second-preimage oracle from a DB read cannot succeed
// without the server key (KEYS-002). The unkeyed path is retained ONLY as a
// nil-key fallback for unit tests; production always supplies a key.
func (m *Manager) hashToken(token string) []byte {
	if m.keyedHashing() {
		return crypto.Sign(m.hmacKey, []byte(token))
	}
	// Fallback: unkeyed SHA-256 (dev/test only; production has hmacKey).
	return legacyHashToken(token)
}

func (m *Manager) keyedHashing() bool { return len(m.hmacKey) == crypto.KeySize }

func legacyHashToken(token string) []byte {
	return crypto.Hash([]byte(token))
}

// RandomToken returns a high-entropy random hex string (e.g. an OAuth state or
// nonce). It draws from the crypto provider so a FIPS build governs the RNG.
func RandomToken() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
