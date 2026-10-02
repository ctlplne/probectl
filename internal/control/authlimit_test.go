// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// U-024 brute-force test: hammering an auth endpoint from one source locks
// that source (429 + Retry-After) while other sources keep working, and the
// lockout lands in the log/audit seam.
func TestAuthBruteForceLockout(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr: ":0", AuthMode: "session",
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthRateMaxFailures: 3, AuthRateWindow: time.Minute, AuthRateLockout: time.Minute,
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	var lockouts int
	base := s.authLimiter.OnLockout
	s.authLimiter.OnLockout = func(key string, failures int, d time.Duration) {
		lockouts++
		if base != nil {
			base(key, failures, d)
		}
	}

	// AUTHZ-04: the gate counts FAILURES, so drive real failed attempts — a
	// callback with an invalid oauth state (400), not a request that merely
	// reaches an unconfigured handler.
	hit := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// AUTHZ-04: the gate counts FAILURES, so the first maxFailures (3) failed
	// callbacks are counted (400) and the NEXT request is locked (429).
	for i := 0; i < 3; i++ {
		if rec := hit("198.51.100.7:4444"); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status %d, want 400 (failed callback)", i+1, rec.Code)
		}
	}
	// The next attempt after the budget is exhausted is locked.
	rec := hit("198.51.100.7:4444")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-budget attempt: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	// Still locked.
	if rec := hit("198.51.100.7:4444"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked source: status %d, want 429", rec.Code)
	}
	// A different source is unaffected.
	if rec := hit("203.0.113.9:5555"); rec.Code != http.StatusBadRequest {
		t.Fatalf("other source: status %d, want 400", rec.Code)
	}
	if lockouts != 1 {
		t.Fatalf("lockout events = %d, want exactly 1", lockouts)
	}
}

// The callback shares the same per-IP gate.
func TestAuthCallbackThrottled(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr: ":0", AuthMode: "session",
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthRateMaxFailures: 1, AuthRateWindow: time.Minute, AuthRateLockout: time.Minute,
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x", nil)
		req.RemoteAddr = "192.0.2.50:1000"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	// maxFailures=1: the first failed callback is counted (400), the next is locked.
	if c := call(); c != http.StatusBadRequest {
		t.Fatalf("first failed callback: status %d, want 400", c)
	}
	if c := call(); c != http.StatusTooManyRequests {
		t.Fatalf("second attempt: status %d, want 429 (locked after 1 failure)", c)
	}
}

func TestSplitAcctKey(t *testing.T) {
	if tid, email, ok := splitAcctKey("acct:t-1:user@example.com"); !ok || tid != "t-1" || email != "user@example.com" {
		t.Fatalf("splitAcctKey = %q %q %v", tid, email, ok)
	}
	for _, bad := range []string{"ip:1.2.3.4", "acct:", "acct:onlytenant", "acct::email"} {
		if _, _, ok := splitAcctKey(bad); ok {
			t.Errorf("splitAcctKey(%q) should fail", bad)
		}
	}
}

// TestAuthLimiterKeysOnTheForwardedClientBehindATrustedProxy (DPR-039): behind
// the shipped ingress every request arrives from the ingress pod, so without
// trusted proxies one client's failures locked SSO for the whole deployment.
// With the ingress declared trusted the limiter keys on X-Forwarded-For; a
// peer outside the trusted set cannot spoof its way onto someone else's key.
func TestAuthLimiterKeysOnTheForwardedClientBehindATrustedProxy(t *testing.T) {
	trusted, err := auth.ParseTrustedProxies([]string{"10.244.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		HTTPAddr: ":0", AuthMode: "session",
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthRateMaxFailures: 2, AuthRateWindow: time.Minute, AuthRateLockout: time.Minute,
		TrustedProxies: trusted,
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)
	hit := func(remote, forwarded string) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	// Client A behind the ingress: two failures (maxFailures=2) are counted,
	// then its next request is locked. Keying is on the forwarded client.
	if c := hit("10.244.0.7:1", "203.0.113.9"); c != http.StatusBadRequest {
		t.Fatalf("A first: %d", c)
	}
	if c := hit("10.244.0.7:2", "203.0.113.9"); c != http.StatusBadRequest {
		t.Fatalf("A second: %d, want 400 (counted, not yet locked)", c)
	}
	// ...client B, arriving through the same ingress pod, is unaffected.
	if c := hit("10.244.0.7:3", "198.51.100.4"); c != http.StatusBadRequest {
		t.Fatalf("B behind the same ingress must not inherit A's lockout: %d", c)
	}
	// A cannot escape by appending a fake hop: the ingress's own append is the
	// rightmost entry, A's forged hop sits to its left, so A stays its own key
	// and is now locked.
	if c := hit("10.244.0.7:4", "198.51.100.200, 203.0.113.9"); c != http.StatusTooManyRequests {
		t.Fatalf("A with a forged left-hand hop must be locked: %d", c)
	}
	// A direct peer outside the trusted set is keyed on itself, header or not:
	// two failures counted, then locked.
	if c := hit("192.0.2.77:5", "198.51.100.4"); c != http.StatusBadRequest {
		t.Fatalf("untrusted peer first: %d", c)
	}
	if c := hit("192.0.2.77:6", "198.51.100.5"); c != http.StatusBadRequest {
		t.Fatalf("untrusted peer second: %d, want 400 (counted)", c)
	}
	if c := hit("192.0.2.77:7", "198.51.100.6"); c != http.StatusTooManyRequests {
		t.Fatalf("untrusted peer keyed on its own address must be locked: %d", c)
	}
}

// AUTHZ-04: the auth gate must count only FAILURES, not every request, so a
// flood of non-failing requests from one (shared ingress) IP cannot lock a
// source out, while genuine failures still do.
func TestAuthThrottleCountsOnlyFailures(t *testing.T) {
	cfg := &config.Config{
		HTTPAddr: ":0", AuthMode: "session",
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthRateMaxFailures: 3, AuthRateWindow: time.Minute, AuthRateLockout: time.Minute,
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	get := func(path, remote string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// 50 non-failing /auth/login requests from one IP: the SSO provider is
	// unconfigured (503, an infrastructure condition, not an auth failure), so
	// none is counted and none is throttled.
	for i := 0; i < 50; i++ {
		if c := get("/auth/login", "198.51.100.10:1"); c == http.StatusTooManyRequests {
			t.Fatalf("request %d from one IP was throttled though none failed: %d", i+1, c)
		}
	}

	// Genuine failures (invalid callback state) from a fresh IP still lock it
	// after the configured number of failures.
	for i := 0; i < 3; i++ {
		if c := get("/auth/callback?state=x", "198.51.100.11:1"); c != http.StatusBadRequest {
			t.Fatalf("failed callback %d: status %d, want 400", i+1, c)
		}
	}
	if c := get("/auth/callback?state=x", "198.51.100.11:1"); c != http.StatusTooManyRequests {
		t.Fatalf("attempt after 3 failures: status %d, want 429 (locked)", c)
	}
}
