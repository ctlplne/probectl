package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	m := NewManager(st, time.Hour, true)
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
	m := NewManager(newFakeStore(), time.Hour, false)
	for _, tok := range []string{"", "deadbeef"} {
		s, err := m.Resolve(context.Background(), tok)
		if err != nil || s != nil {
			t.Fatalf("token %q: want nil,nil got %v,%v", tok, s, err)
		}
	}
}

func TestManagerExpiredSession(t *testing.T) {
	st := newFakeStore()
	m := NewManager(st, time.Hour, false)
	// Insert a session whose expiry is already in the past (the store filters
	// expired rows; the manager hashes the lookup token the same way).
	_ = st.Create(context.Background(), hashToken("expired-tok"),
		Session{TenantID: "t1", UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute)})
	if s, _ := m.Resolve(context.Background(), "expired-tok"); s != nil {
		t.Fatal("expired session should not resolve")
	}
}

func TestSetCookieAttributes(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, true)
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
	m := NewManager(newFakeStore(), time.Hour, false)
	rec := httptest.NewRecorder()
	m.SetCookie(rec, "x")
	if rec.Result().Cookies()[0].Secure {
		t.Error("cookie must not be Secure when secure=false (plain-HTTP dev)")
	}
}

func TestClearCookieExpires(t *testing.T) {
	m := NewManager(newFakeStore(), time.Hour, true)
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
	m := NewManager(st, time.Hour, false)
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
