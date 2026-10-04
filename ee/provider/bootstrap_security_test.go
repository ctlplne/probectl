// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// AUD-14: the read-only ladder (S-T0) blocks creating the FIRST admin too.
// The provider handler is mounted whenever the provider plane is licensed, and
// lic.Has(FeatureProviderPlane) stays true in read_only mode, so an expired
// (past-grace) deployment used to still bootstrap a new admin via
// POST /provider/v1/auth/bootstrap — contrary to docs/provider-plane.md
// (commercial features go read-only on expiry). Bootstrap must refuse with
// ErrReadOnly and create NO operator, mirroring CreateOperator; a writable
// (active) license still bootstraps.
func TestBootstrapBlockedWhenReadOnly(t *testing.T) {
	ctx := context.Background()

	// Read-only: license expired 31 days ago (past the 30-day grace).
	ro := newFixture(t, licenseManager(t, license.TierMSP, 0, -31*24*time.Hour))
	if n, err := ro.store.CountOperators(ctx); err != nil || n != 0 {
		t.Fatalf("precondition: empty roster expected, got %d (err %v)", n, err)
	}

	op, enroll, err := ro.svc.Bootstrap(ctx, bootToken, bootToken, "root@msp.example", "Root")
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only Bootstrap: err = %v, want ErrReadOnly (the degraded license must not create the first admin)", err)
	}
	if (op != Operator{}) || enroll != "" {
		t.Fatalf("read-only Bootstrap returned a created operator/token (%+v, %q); it must create nothing", op, enroll)
	}
	if n, err := ro.store.CountOperators(ctx); err != nil || n != 0 {
		t.Fatalf("read-only Bootstrap created an operator: roster now %d (err %v), want 0", n, err)
	}

	// HTTP surface: the public bootstrap route answers 403 license_read_only.
	rec := doReq(ro.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": bootToken, "email": "root@msp.example", "name": "Root"}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("POST bootstrap in read-only: got %d %s, want 403 license_read_only", rec.Code, rec.Body.String())
	}

	// A writable (active) license still bootstraps the first admin.
	active := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	op, enroll, err = active.svc.Bootstrap(ctx, bootToken, bootToken, "root@msp.example", "Root")
	if err != nil {
		t.Fatalf("active Bootstrap: unexpected err %v", err)
	}
	if op.ID == "" || op.Role != RoleAdmin || enroll == "" {
		t.Fatalf("active Bootstrap: got op %+v enroll %q, want an admin operator + enroll token", op, enroll)
	}
	if n, err := active.store.CountOperators(ctx); err != nil || n != 1 {
		t.Fatalf("active Bootstrap: roster = %d (err %v), want 1", n, err)
	}
}

// AUTHZ-24: the provider bootstrap endpoint is PUBLIC and gated only by a static
// token, so it is brute-force throttled per source IP with the same brake as the
// operator login — the 6th bad attempt in the window is refused with 429 before
// the token is even checked.
func TestBootstrapThrottlePerIP(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))

	attempt := func() int {
		rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
			map[string]string{"token": "a-wrong-bootstrap-token", "email": "x@y.example", "name": "X"}))
		return rec.Code
	}

	// The default limiter trips after 5 failures: attempts 1-5 reach the token
	// check and are refused 403; the 6th is throttled 429.
	for i := 1; i <= 5; i++ {
		if got := attempt(); got != http.StatusForbidden {
			t.Fatalf("bad bootstrap attempt %d: got %d, want 403 before the limiter trips", i, got)
		}
	}
	if got := attempt(); got != http.StatusTooManyRequests {
		t.Fatalf("6th bad bootstrap attempt: got %d, want 429 (AUTHZ-24: endpoint not throttled)", got)
	}
}

// AUTHZ-24: once bootstrap is CLOSED (the first admin exists), the endpoint must
// answer IDENTICALLY whether the presented token is right or wrong — otherwise
// the 403-vs-409 difference is an oracle confirming the static bootstrap token.
func TestBootstrapClosedResponseIsUniform(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))

	// Close bootstrap by creating the first admin (also clears the limiter via
	// the success path, so the two probes below are not throttled).
	f.bootstrapAndLogin(t)

	wrong := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": "a-wrong-bootstrap-token", "email": "w@msp.example", "name": "W"}))
	right := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": bootToken, "email": "r@msp.example", "name": "R"}))

	if wrong.Code != http.StatusForbidden {
		t.Fatalf("closed bootstrap with a wrong token: got %d, want 403", wrong.Code)
	}
	if right.Code != wrong.Code || right.Body.String() != wrong.Body.String() {
		t.Fatalf("closed bootstrap must answer identically for right vs wrong token, but got %d %q (right) vs %d %q (wrong) — the 403-vs-409 oracle persists (AUTHZ-24)",
			right.Code, right.Body.String(), wrong.Code, wrong.Body.String())
	}
}
