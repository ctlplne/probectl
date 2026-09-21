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

	hit := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Attempts below the threshold reach the handler (SSO unconfigured -> 503).
	for i := 0; i < 2; i++ {
		if rec := hit("198.51.100.7:4444"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: status %d, want 503 (handler reached)", i+1, rec.Code)
		}
	}
	// The threshold attempt trips the lockout.
	rec := hit("198.51.100.7:4444")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("lockout attempt: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	// Still locked.
	if rec := hit("198.51.100.7:4444"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked source: status %d, want 429", rec.Code)
	}
	// A different source is unaffected.
	if rec := hit("203.0.113.9:5555"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("other source: status %d, want 503", rec.Code)
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

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=x", nil)
	req.RemoteAddr = "192.0.2.50:1000"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("first attempt with maxFailures=1: status %d, want 429 (immediate lock)", rec.Code)
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
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	// Client A behind the ingress trips its own lockout...
	if c := hit("10.244.0.7:1", "203.0.113.9"); c != http.StatusServiceUnavailable {
		t.Fatalf("A first: %d", c)
	}
	if c := hit("10.244.0.7:2", "203.0.113.9"); c != http.StatusTooManyRequests {
		t.Fatalf("A second (threshold 2): %d, want 429", c)
	}
	// ...and client B, arriving through the same ingress pod, is unaffected.
	if c := hit("10.244.0.7:3", "198.51.100.4"); c != http.StatusServiceUnavailable {
		t.Fatalf("B behind the same ingress must not inherit A's lockout: %d", c)
	}
	// A cannot escape by appending a fake hop: the ingress's own append is
	// the rightmost entry, and A's forged hop sits to its left.
	if c := hit("10.244.0.7:4", "198.51.100.200, 203.0.113.9"); c != http.StatusTooManyRequests {
		t.Fatalf("A with a forged left-hand hop must stay locked: %d", c)
	}
	// A direct peer outside the trusted set is keyed on itself, header or not.
	if c := hit("192.0.2.77:5", "198.51.100.4"); c != http.StatusServiceUnavailable {
		t.Fatalf("untrusted peer first: %d", c)
	}
	if c := hit("192.0.2.77:6", "198.51.100.5"); c != http.StatusTooManyRequests {
		t.Fatalf("untrusted peer must be keyed on its own address regardless of the header: %d", c)
	}
}
