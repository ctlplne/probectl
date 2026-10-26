// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.
package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestQuarantineLoginBrowserRecovery(t *testing.T) {
	const tenant = "33333333-3333-3333-3333-333333333333"
	err := &tenancy.QuarantinedError{Entry: tenancy.QuarantineEntry{TenantID: tenant, Reason: tenancy.QuarantinePlaneMissing, Plane: `<script>alert(1)</script>`, Detail: "operator-private-detail"}}
	for _, tc := range []struct {
		name, path, accept string
		html               bool
	}{
		{"browser", "/auth/login?tenant=" + tenant, "text/html,application/xhtml+xml", true},
		{"default", "/auth/login", "text/html", true},
		{"invalid routing", "/auth/login?tenant=bad&code=secret&return=https://evil.example", "text/html", true},
		{"api client", "/auth/login?tenant=" + tenant, "application/json", false},
		{"unspecified", "/auth/login", "", false},
		{"html refused", "/auth/login", "text/html;q=0,application/json", false},
		{"API route", "/v1/tests", "text/html", false},
		{"callback", "/auth/callback?code=secret", "text/html", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()
			writeError(rec, req, err)
			body := rec.Body.String()
			if rec.Code != 503 {
				t.Fatalf("status=%d", rec.Code)
			}
			if strings.Contains(body, "operator-private-detail") || strings.Contains(body, "<script>") {
				t.Fatal("unsafe detail in refusal")
			}
			if tc.html {
				if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "Retry sign-in") || !strings.Contains(body, "tenant_quarantined") {
					t.Fatalf("missing browser recovery: %s", body)
				}
				retry := "/auth/login"
				console := "/ui/"
				if strings.Contains(tc.path, "tenant="+tenant) {
					retry += "?tenant=" + tenant
					console += "?login_tenant=" + tenant
				}
				if !strings.Contains(body, `href="`+retry+`"`) || !strings.Contains(body, `href="`+console+`"`) {
					t.Fatalf("tenant routing lost: %s", body)
				}
				if strings.Contains(body, "secret") || strings.Contains(body, "evil.example") {
					t.Fatal("untrusted query reflected")
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("login error may be cached")
				}
			} else if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
				t.Fatal("JSON contract changed")
			}
		})
	}
}
