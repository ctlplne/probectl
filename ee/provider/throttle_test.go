// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// SEC-003: the provider/operator login — the HIGHEST-privilege login in the
// product — is brute-force throttled per account + per IP with exponential
// lockout, and lockouts land in the provider audit stream. (The tenant login
// has had this since U-024; this closes the provider-plane gap.)
func TestProviderLoginThrottleLockout(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))

	// attempt returns the status + Retry-After header (closing the body) — the
	// only things this test asserts on, so no *http.Response escapes (bodyclose).
	attempt := func(email, pw string) (int, string) {
		rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
			map[string]string{"email": email, "password": pw}))
		resp := rec.Result()
		defer resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}

	// Hammer a (nonexistent) account: the first failures are 401/403; once
	// the limiter trips, the answer becomes 429 BEFORE authentication runs.
	var saw429 bool
	var retryAfter string
	for i := 0; i < 12; i++ {
		status, ra := attempt("attacker-target@msp.example", "wrong-password")
		retryAfter = ra
		if status == http.StatusTooManyRequests {
			saw429 = true
			break
		}
		if status != http.StatusForbidden && status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: unexpected status %d", i, status)
		}
	}
	if !saw429 {
		t.Fatal("repeated bad provider logins were never throttled (SEC-003)")
	}
	if retryAfter == "" {
		t.Fatal("throttled response must carry Retry-After")
	}

	// Locked means locked: the very next attempt is refused without touching
	// the password path (still 429).
	if got, _ := attempt("attacker-target@msp.example", "wrong-password"); got != http.StatusTooManyRequests {
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
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))

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
