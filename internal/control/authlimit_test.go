// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
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
