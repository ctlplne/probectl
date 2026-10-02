// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// providerSessionCookieName is the provider-operator session cookie on the wire.
// Spelled as a literal (not auth.ProviderSessionCookie) so this regression
// compiles against the pre-fix tree, where the guard existed but recognized only
// the tenant cookie and the constant did not yet exist — the assertion, not a
// build error, is what must go red.
const providerSessionCookieName = "probectl_provider_session"

// TestCSRFGuardCoversProviderOperatorCookie is the AUTHZ-05 reopen regression:
// csrfGuard refused cross-origin cookie mutations only for the tenant session
// cookie, so every provider-OPERATOR mutation (POST /provider/v1/tenants/{id}/
// suspend|offboard|erase, create operator, break-glass) rode the SameSite=Strict
// operator cookie with no origin check — exploitable from a sibling subdomain,
// the finding's MSP threat model.
func TestCSRFGuardCoversProviderOperatorCookie(t *testing.T) {
	// A request carrying only the operator cookie must count as cookie-authed.
	r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/t1/suspend", nil)
	r.AddCookie(&http.Cookie{Name: providerSessionCookieName, Value: "op-session"})
	if !cookieAuthenticated(r) {
		t.Fatal("provider-operator session cookie must count as cookie-authenticated")
	}

	srv := &Server{}

	// A cross-origin operator mutation (no body — the path-param suspend route)
	// must be refused 403 before the handler runs.
	cross := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/t1/suspend", nil)
	cross.Host = "console.msp.example"
	cross.Header.Set("Origin", "https://attacker.msp.example")
	cross.AddCookie(&http.Cookie{Name: providerSessionCookieName, Value: "op-session"})
	rec := httptest.NewRecorder()
	reached := false
	srv.csrfGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(rec, cross)
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin provider-operator mutation: reached=%v code=%d, want blocked 403", reached, rec.Code)
	}

	// A same-origin operator mutation is admitted (the guard must not break the
	// legitimate console).
	same := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/t1/suspend", nil)
	same.Host = "console.msp.example"
	same.Header.Set("Origin", "https://console.msp.example")
	same.AddCookie(&http.Cookie{Name: providerSessionCookieName, Value: "op-session"})
	rec = httptest.NewRecorder()
	reached = false
	srv.csrfGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(rec, same)
	if !reached {
		t.Fatalf("same-origin provider-operator mutation was blocked (code=%d); the console must still work", rec.Code)
	}
}
