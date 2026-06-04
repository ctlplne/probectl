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
	store  SessionStore
	ttl    time.Duration
	secure bool
}

// NewManager builds a session manager. secure controls the cookie's Secure flag
// (true in production behind HTTPS; false only for plain-HTTP dev/test).
func NewManager(store SessionStore, ttl time.Duration, secure bool) *Manager {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Manager{store: store, ttl: ttl, secure: secure}
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
	if err := m.store.Create(ctx, hashToken(token), sess); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve returns the session for a token, or (nil, nil) if there is none/expired.
func (m *Manager) Resolve(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	return m.store.LookupByHash(ctx, hashToken(token))
}

// Revoke deletes a session (logout).
func (m *Manager) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return m.store.DeleteByHash(ctx, hashToken(token))
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
// is the secret and is never stored in the clear).
func hashToken(token string) []byte {
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
