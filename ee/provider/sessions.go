// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
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
	op           Operator
	expires      time.Time
	lastActivity time.Time
}

// Sessions is the in-memory operator-session store.
type Sessions struct {
	mu      sync.Mutex
	byH     map[string]opSession
	now     func() time.Time
	idle    time.Duration
	hmacKey []byte // PROBECTL_SESSION_HMAC_KEY (KEYS-002); must be 32 bytes
	// store, when set, is the source of truth shared by every replica; the
	// map above is then unused. Nil keeps the single-process behavior.
	store SessionStore
}

// NewSessions returns an empty operator-session store. hmacKey should be the
// same 32-byte key used by the tenant session manager (PROBECTL_SESSION_HMAC_KEY)
// so both session domains benefit from keyed hashing (KEYS-002). Pass nil only
// in tests; production always supplies a key.
func NewSessions(hmacKey []byte) *Sessions {
	return &Sessions{
		byH: map[string]opSession{}, now: time.Now,
		idle: auth.DefaultSessionIdleTimeout, hmacKey: hmacKey,
	}
}

// WithIdleTimeout applies the same configurable, default-on inactivity window
// as tenant sessions. Zero cannot silently create unlimited provider access.
func (s *Sessions) WithIdleTimeout(idle time.Duration) *Sessions {
	if idle > 0 {
		s.idle = idle
	}
	return s
}

// SessionStore persists operator sessions so that every control replica
// validates the same session and a revocation reaches all of them (DPR-033).
// Only the keyed token hash is stored; GetSession returns the operator row as
// it is NOW, so a disabled operator's session dies on every replica at once.
type SessionStore interface {
	PutSession(ctx context.Context, tokenHash, operatorID string, expires, lastActivity time.Time) error
	GetSession(ctx context.Context, tokenHash string) (op Operator, expires, lastActivity time.Time, found bool, err error)
	TouchSession(ctx context.Context, tokenHash string, lastActivity time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteOperatorSessions(ctx context.Context, operatorID string) error
}

// touchInterval bounds how often an active session's last-activity row is
// rewritten; idle timeouts are minutes to hours, so second-level precision is
// wasted writes.
const touchInterval = time.Minute

// WithStore makes the sessions replica-safe: issued, resolved and revoked
// through the shared store instead of this process's memory (DPR-033).
func (s *Sessions) WithStore(store SessionStore) *Sessions {
	s.store = store
	return s
}

func (s *Sessions) Issue(op Operator) (string, error) {
	return s.IssueContext(context.Background(), op)
}

func (s *Sessions) IssueContext(ctx context.Context, op Operator) (string, error) {
	raw, err := crypto.Random(32)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := s.now()
	if s.store != nil {
		if err := s.store.PutSession(ctx, s.hashKey(token), op.ID, now.Add(sessionTTL), now); err != nil {
			return "", err
		}
		return token, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byH[s.hashKey(token)] = opSession{op: op, expires: now.Add(sessionTTL), lastActivity: now}
	return token, nil
}

func (s *Sessions) Resolve(token string) *Operator {
	return s.ResolveContext(context.Background(), token)
}

// ResolveContext returns the operator behind a live session, or nil. A store
// failure denies (fail closed) rather than falling back to process memory.
func (s *Sessions) ResolveContext(ctx context.Context, token string) *Operator {
	if token == "" {
		return nil
	}
	h := s.hashKey(token)
	now := s.now()
	if s.store != nil {
		op, expires, last, found, err := s.store.GetSession(ctx, h)
		if err != nil || !found {
			return nil
		}
		if now.After(expires) || !last.After(now.Add(-s.idle)) {
			_ = s.store.DeleteSession(ctx, h)
			return nil
		}
		if now.Sub(last) >= touchInterval {
			if err := s.store.TouchSession(ctx, h, now); err != nil {
				return nil
			}
		}
		return &op
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byH[h]
	if !ok || now.After(sess.expires) || !sess.lastActivity.After(now.Add(-s.idle)) {
		delete(s.byH, h)
		return nil
	}
	sess.lastActivity = now
	s.byH[h] = sess
	op := sess.op
	return &op
}

func (s *Sessions) Revoke(token string) { s.RevokeContext(context.Background(), token) }

func (s *Sessions) RevokeContext(ctx context.Context, token string) {
	if token == "" {
		return
	}
	if s.store != nil {
		_ = s.store.DeleteSession(ctx, s.hashKey(token))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byH, s.hashKey(token))
}

func (s *Sessions) RevokeOperator(operatorID string) {
	s.RevokeOperatorContext(context.Background(), operatorID)
}

func (s *Sessions) RevokeOperatorContext(ctx context.Context, operatorID string) {
	if s.store != nil {
		_ = s.store.DeleteOperatorSessions(ctx, operatorID)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.byH {
		if sess.op.ID == operatorID {
			delete(s.byH, h)
		}
	}
}

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
