// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// AUTHZ-05: cookie-authenticated state-changing requests had no CSRF protection
// beyond SameSite=Lax. A form-safe Content-Type (text/plain) must be refused 415
// and a cross-origin mutation driven by the session cookie must be refused 403,
// while bearer-token calls are unaffected.
func TestCSRFProtectsCookieMutations(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "csrf")
	uid := createUserWithPerm(t, db, tenant, "csrf@x.com", nil, "test.write")
	sess, err := srv.sessions.Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: uid, Email: "csrf@x.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"name":"c","type":"icmp","target":"1.1.1.1"}`

	// httptest.NewRequest defaults Host to "example.com".
	do := func(ct, origin, bearer string, cookie bool) int {
		r := httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sess})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		// The control plane rotates the session cookie; follow the replacement
		// like a browser so a later request isn't rejected as a stale session.
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.SessionCookie && c.Value != "" {
				sess = c.Value
			}
		}
		return rec.Code
	}

	// (a) A form-safe Content-Type on a cookie mutation is refused 415.
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
		if c := do(ct, "https://example.com", "", true); c != http.StatusUnsupportedMediaType {
			t.Fatalf("cookie mutation with Content-Type %q = %d, want 415", ct, c)
		}
	}
	// (b) A cross-origin cookie mutation (even with application/json) is refused 403.
	if c := do("application/json", "https://wiki.corp.example", "", true); c != http.StatusForbidden {
		t.Fatalf("cross-origin cookie mutation = %d, want 403", c)
	}
	// (c) A same-origin application/json cookie mutation is NOT blocked by CSRF
	//     (it reaches the handler — here 201).
	if c := do("application/json", "https://example.com", "", true); c == http.StatusUnsupportedMediaType || c == http.StatusForbidden {
		t.Fatalf("same-origin json cookie mutation was blocked = %d", c)
	}
	// (d) A bearer-carrying request is exempt from the CSRF origin check (no
	//     ambient cookie); a cross-origin bearer request is never a CSRF 403.
	if c := do("application/json", "https://wiki.corp.example", "bogus-token", false); c == http.StatusForbidden {
		t.Fatalf("bearer request must not be refused by the CSRF origin check, got 403")
	}
}
