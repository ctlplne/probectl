// SPDX-License-Identifier: LicenseRef-probectl-TBD

package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// fakeStore is an in-memory SessionStore for unit tests.
type fakeStore struct {
	byHash map[string]Session
}

func newFakeStore() *fakeStore { return &fakeStore{byHash: map[string]Session{}} }

func (f *fakeStore) Create(_ context.Context, h []byte, s Session) error {
	f.byHash[string(h)] = s
	return nil
}

func (f *fakeStore) LookupByHash(_ context.Context, h []byte) (*Session, error) {
	s, ok := f.byHash[string(h)]
	if !ok || s.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	return &s, nil
}

func (f *fakeStore) DeleteByHash(_ context.Context, h []byte) error {
	delete(f.byHash, string(h))
	return nil
}

func TestManagerIssueResolveRevoke(t *testing.T) {
	st := newFakeStore()
	m := NewManager(st, time.Hour, true, nil)
	ctx := context.Background()

	token, err := m.Issue(ctx, Session{TenantID: "t1", UserID: "u1", Email: "a@b.c"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	// The opaque token must never be stored verbatim — only its hash.
	if _, stored := st.byHash[token]; stored {
		t.Fatal("token stored in the clear (must store only the hash)")
	}

	sess, err := m.Resolve(ctx, token)
	if err != nil || sess == nil {
		t.Fatalf("resolve: %v sess=%v", err, sess)
	}
	if sess.TenantID != "t1" || sess.UserID != "u1" {
		t.Fatalf("wrong session: %+v", sess)
	}

	if err := m.Revoke(ctx, token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	sess, _ = m.Resolve(ctx, token)
	if sess != nil {
		t.Fatal("session still resolvable after revoke")
	}
}

func TestManagerResolveUnknownAndEmpty(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, false, nil)
	for _, tok := range []string{"", "deadbeef"} {
		s, err := m.Resolve(context.Background(), tok)
		if err != nil || s != nil {
			t.Fatalf("token %q: want nil,nil got %v,%v", tok, s, err)
		}
	}
}

func TestManagerExpiredSession(t *testing.T) {
	st := newFakeStore()
	m := NewManager(st, time.Hour, false, nil)
	// Insert a session whose expiry is already in the past (the store filters
	// expired rows; the manager hashes the lookup token the same way).
	_ = st.Create(context.Background(), m.hashToken("expired-tok"),
		Session{TenantID: "t1", UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute)})
	if s, _ := m.Resolve(context.Background(), "expired-tok"); s != nil {
		t.Fatal("expired session should not resolve")
	}
}

func TestSetCookieAttributes(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, true, nil)
	rec := httptest.NewRecorder()
	m.SetCookie(rec, "tok123")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookie || c.Value != "tok123" {
		t.Fatalf("wrong cookie: %+v", c)
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie must be Secure when secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("want SameSite=Lax, got %v", c.SameSite)
	}
}

func TestSetCookieInsecureMode(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, false, nil)
	rec := httptest.NewRecorder()
	m.SetCookie(rec, "x")
	if rec.Result().Cookies()[0].Secure {
		t.Error("cookie must not be Secure when secure=false (plain-HTTP dev)")
	}
}

func TestClearCookieExpires(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, true, nil)
	rec := httptest.NewRecorder()
	m.ClearCookie(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Errorf("clear must set MaxAge<0, got %d", c.MaxAge)
	}
}

func TestTokenFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := TokenFromRequest(r); got != "" {
		t.Fatalf("no cookie should yield empty, got %q", got)
	}
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "abc"})
	if got := TokenFromRequest(r); got != "abc" {
		t.Fatalf("want abc, got %q", got)
	}
}

func TestRandomTokenUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := RandomToken()
		if err != nil {
			t.Fatalf("RandomToken: %v", err)
		}
		if len(tok) < 16 {
			t.Fatalf("token too short: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token: %q", tok)
		}
		seen[tok] = true
	}
}

func TestPrincipalHas(t *testing.T) {
	var nilP *Principal
	if nilP.Has("x") {
		t.Error("nil principal must not hold any permission")
	}
	p := &Principal{Permissions: map[string]bool{"test.read": true}}
	if !p.Has("test.read") {
		t.Error("want test.read")
	}
	if p.Has("test.write") {
		t.Error("must not have test.write")
	}
}

// fakePerms is a PermissionLoader returning a fixed set.
type fakePerms struct {
	keys []string
	err  error
}

func (f fakePerms) ForUser(context.Context, string, string) ([]string, error) {
	return f.keys, f.err
}

func TestAuthenticatorResolve(t *testing.T) {
	st := newFakeStore()
	m := NewManager(st, time.Hour, false, nil)
	token, _ := m.Issue(context.Background(), Session{TenantID: "t1", UserID: "u1", Email: "a@b.c"})
	a := NewAuthenticator(m, fakePerms{keys: []string{"test.read", "agent.read"}})

	// No cookie → nil principal.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if p, err := a.Resolve(r); err != nil || p != nil {
		t.Fatalf("no-cookie: want nil,nil got %v,%v", p, err)
	}

	// Valid cookie → principal with loaded permissions.
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	p, err := a.Resolve(r)
	if err != nil || p == nil {
		t.Fatalf("resolve: %v p=%v", err, p)
	}
	if p.TenantID != "t1" || p.Email != "a@b.c" {
		t.Fatalf("wrong principal: %+v", p)
	}
	if !p.Has("test.read") || !p.Has("agent.read") || p.Has("test.write") {
		t.Fatalf("wrong permissions: %v", p.Permissions)
	}
}

// TestHashTokenKeyedHMAC is the KEYS-002 acceptance test: proves that when the
// Manager is built with a 32-byte HMAC key, hashToken produces HMAC-SHA256
// (not unkeyed SHA-256), that a known token produces a deterministic keyed
// digest, and that two managers with DIFFERENT keys produce DIFFERENT digests
// for the same token (confirming the key is load-bearing).
//
// Fails pre-fix (hashToken ignored the key; always returned SHA-256); passes
// post-fix.
func TestHashTokenKeyedHMAC(t *testing.T) {
	// 32-byte HMAC key (PROBECTL_SESSION_HMAC_KEY equivalent in test).
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}

	mKeyed := NewManager(newFakeStore(), time.Hour, false, key)
	mUnkeyed := NewManager(newFakeStore(), time.Hour, false, nil)

	token := "test-session-token-abc123"

	keyedHash := mKeyed.hashToken(token)
	unkeyedHash := mUnkeyed.hashToken(token)

	// Keyed and unkeyed must differ; the key is load-bearing.
	if bytes.Equal(keyedHash, unkeyedHash) {
		t.Fatal("KEYS-002: keyed HMAC must differ from unkeyed SHA-256")
	}

	// Keyed hash must equal crypto.Sign(key, token), not SHA-256.
	want := crypto.Sign(key, []byte(token))
	if !bytes.Equal(keyedHash, want) {
		t.Fatalf("KEYS-002: keyed hash = %x, want HMAC %x", keyedHash, want)
	}

	// A second DIFFERENT key must produce a different hash (key isolation).
	key2 := make([]byte, crypto.KeySize)
	for i := range key2 {
		key2[i] = byte(i + 100)
	}
	mKeyed2 := NewManager(newFakeStore(), time.Hour, false, key2)
	if bytes.Equal(mKeyed.hashToken(token), mKeyed2.hashToken(token)) {
		t.Fatal("KEYS-002: two managers with distinct keys must produce distinct hashes")
	}
}

// TestManagerKeyedHMACEndToEnd proves the full Issue/Resolve/Revoke cycle
// works correctly under the keyed-HMAC path (KEYS-002). This is the production
// path wired in by NewManager with PROBECTL_SESSION_HMAC_KEY.
func TestManagerKeyedHMACEndToEnd(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	st := newFakeStore()
	m := NewManager(st, time.Hour, true, key)
	ctx := context.Background()

	token, err := m.Issue(ctx, Session{TenantID: "t1", UserID: "u1", Email: "a@b.c"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The stored key must be the HMAC of the token, not the token itself.
	hmacOfToken := crypto.Sign(key, []byte(token))
	if _, ok := st.byHash[string(token)]; ok {
		t.Fatal("token stored in the clear (must store only the keyed hash)")
	}
	if _, ok := st.byHash[string(hmacOfToken)]; !ok {
		t.Fatal("keyed HMAC of token not found in store")
	}

	sess, err := m.Resolve(ctx, token)
	if err != nil || sess == nil {
		t.Fatalf("resolve: %v sess=%v", err, sess)
	}

	if err := m.Revoke(ctx, token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if s, _ := m.Resolve(ctx, token); s != nil {
		t.Fatal("session still resolvable after revoke")
	}
}

// TestManagerKeyedHMACReadsLegacyUntilTTL is the KEYS-002 compatibility guard:
// a deployment that starts using PROBECTL_SESSION_HMAC_KEY must not instantly
// log out every persisted session that was created under the old unkeyed digest.
// New sessions are keyed, but reads fall back to the legacy digest until those
// old rows expire by normal TTL.
func TestManagerKeyedHMACReadsLegacyUntilTTL(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 11)
	}
	st := newFakeStore()
	m := NewManager(st, time.Hour, true, key)
	ctx := context.Background()
	const token = "legacy-session-token"

	if err := st.Create(ctx, legacyHashToken(token), Session{
		TenantID:  "t1",
		UserID:    "u1",
		Email:     "a@b.c",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create legacy row: %v", err)
	}

	sess, err := m.Resolve(ctx, token)
	if err != nil || sess == nil {
		t.Fatalf("resolve legacy row through keyed manager: sess=%v err=%v", sess, err)
	}
	if sess.TenantID != "t1" || sess.UserID != "u1" {
		t.Fatalf("wrong legacy session: %+v", sess)
	}
}

// TestManagerKeyedHMACRevokeDeletesLegacyAndKeyed proves logout closes both
// rows during the KEYS-002 migration window. That matters because otherwise a
// user could log out of the new keyed row while an older unkeyed row remains
// live until TTL.
func TestManagerKeyedHMACRevokeDeletesLegacyAndKeyed(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 21)
	}
	st := newFakeStore()
	m := NewManager(st, time.Hour, true, key)
	ctx := context.Background()
	const token = "dual-session-token"
	live := Session{TenantID: "t1", UserID: "u1", Email: "a@b.c", ExpiresAt: time.Now().Add(time.Hour)}

	if err := st.Create(ctx, m.hashToken(token), live); err != nil {
		t.Fatalf("create keyed row: %v", err)
	}
	if err := st.Create(ctx, legacyHashToken(token), live); err != nil {
		t.Fatalf("create legacy row: %v", err)
	}
	if err := m.Revoke(ctx, token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := st.byHash[string(m.hashToken(token))]; ok {
		t.Fatal("keyed row survived revoke")
	}
	if _, ok := st.byHash[string(legacyHashToken(token))]; ok {
		t.Fatal("legacy row survived revoke")
	}
}
