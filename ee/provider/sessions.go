// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Operator sessions (S-T1): a privilege domain DISTINCT from tenant sessions —
// different cookie, different store, different lifetime. Tokens are opaque;
// only their hash is held (a memory/heap read cannot mint a session). The
// store is in-memory by design: operator sessions are few, short-lived, and
// re-login after a control-plane restart is an acceptable (even desirable)
// property for a high-privilege domain.

// SessionCookie is the provider-domain session cookie name.
const SessionCookie = "probectl_provider_session"

const sessionTTL = 4 * time.Hour

type opSession struct {
	op      Operator
	expires time.Time
}

// Sessions is the in-memory operator-session store.
type Sessions struct {
	mu      sync.Mutex
	byH     map[string]opSession
	now     func() time.Time
	hmacKey []byte // PROBECTL_SESSION_HMAC_KEY (KEYS-002); must be 32 bytes
}

// NewSessions returns an empty operator-session store. hmacKey should be the
// same 32-byte key used by the tenant session manager (PROBECTL_SESSION_HMAC_KEY)
// so both session domains benefit from keyed hashing (KEYS-002). Pass nil only
// in tests; production always supplies a key.
func NewSessions(hmacKey []byte) *Sessions {
	return &Sessions{byH: map[string]opSession{}, now: time.Now, hmacKey: hmacKey}
}

// Issue mints an opaque session token for an authenticated operator.
func (s *Sessions) Issue(op Operator) (string, error) {
	raw, err := crypto.Random(32)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byH[s.hashKey(token)] = opSession{op: op, expires: s.now().Add(sessionTTL)}
	return token, nil
}

// Resolve returns the operator for a token, or nil when absent/expired.
func (s *Sessions) Resolve(token string) *Operator {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hashKey(token)
	sess, ok := s.byH[h]
	if !ok || s.now().After(sess.expires) {
		delete(s.byH, h)
		return nil
	}
	op := sess.op
	return &op
}

// Revoke deletes a session (logout).
func (s *Sessions) Revoke(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byH, s.hashKey(token))
}

// RevokeOperator deletes every session belonging to an operator (used when an
// admin disables an account — access ends immediately, not at TTL).
func (s *Sessions) RevokeOperator(operatorID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.byH {
		if sess.op.ID == operatorID {
			delete(s.byH, h)
		}
	}
}

// hashKey returns the keyed-HMAC (or unkeyed-SHA256 fallback) of token as a
// hex string for use as the map key. Production always has hmacKey set
// (PROBECTL_SESSION_HMAC_KEY; KEYS-002); the fallback exists for tests only.
func (s *Sessions) hashKey(token string) string {
	if len(s.hmacKey) == crypto.KeySize {
		return hex.EncodeToString(crypto.Sign(s.hmacKey, []byte(token)))
	}
	return hex.EncodeToString(crypto.Hash([]byte(token)))
}

// tokenFromRequest reads the operator session token: the provider cookie, or
// a Bearer header (CLI/tests).
func tokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// setCookie writes the provider session cookie: Secure + HttpOnly +
// SameSite=Strict (stricter than the tenant cookie — this domain can reach
// every tenant's lifecycle).
func setCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/provider",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(sessionTTL),
	})
}

func clearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/provider",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}
