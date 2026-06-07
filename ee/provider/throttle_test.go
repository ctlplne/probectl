package provider

import (
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/license"
)

// SEC-003: the provider/operator login — the HIGHEST-privilege login in the
// product — is brute-force throttled per account + per IP with exponential
// lockout, and lockouts land in the provider audit stream. (The tenant login
// has had this since U-024; this closes the provider-plane gap.)
func TestProviderLoginThrottleLockout(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))

	attempt := func(email, pw string) *http.Response {
		rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
			map[string]string{"email": email, "password": pw}))
		return rec.Result()
	}

	// Hammer a (nonexistent) account: the first failures are 401/403; once
	// the limiter trips, the answer becomes 429 BEFORE authentication runs.
	var saw429 bool
	var resp *http.Response
	for i := 0; i < 12; i++ {
		resp = attempt("attacker-target@msp.example", "wrong-password")
		if resp.StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: unexpected status %d", i, resp.StatusCode)
		}
	}
	if !saw429 {
		t.Fatal("repeated bad provider logins were never throttled (SEC-003)")
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("throttled response must carry Retry-After")
	}

	// Locked means locked: the very next attempt is refused without touching
	// the password path (still 429).
	if got := attempt("attacker-target@msp.example", "wrong-password").StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("locked account answered %d, want 429", got)
	}

	// The lockout is audited to the PROVIDER stream (guardrail 7).
	if f.audit.count("provider.auth_lockout") == 0 {
		t.Fatal("lockout did not land in the provider audit stream")
	}
}

// The per-IP dimension trips independently of the account: rotating accounts
// from one source is still throttled.
func TestProviderLoginThrottlePerIP(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))

	var saw429 bool
	for i := 0; i < 12; i++ {
		rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
			map[string]string{"email": "rotating-" + string(rune('a'+i)) + "@msp.example", "password": "wrong"}))
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("account rotation from one IP was never throttled (SEC-003)")
	}
}
