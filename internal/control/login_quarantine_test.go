// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.
package control

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/crypto"
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
				if !strings.Contains(body, `<svg aria-hidden="true"`) || !strings.Contains(body, `</svg> probectl`) {
					t.Fatal("recovery page is missing the fixed probectl name and mark")
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
				assertFixedRecoveryStyle(t, rec)
			} else if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
				t.Fatal("JSON contract changed")
			}
		})
	}
}

func assertFixedRecoveryStyle(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	_, style, found := strings.Cut(body, "<style>")
	style, _, closed := strings.Cut(style, "</style>")
	if !found || !closed || !strings.Contains(body, `<meta name="color-scheme" content="light dark">`) ||
		!strings.Contains(style, "overflow-wrap: anywhere") || !strings.Contains(style, ".attribution:focus-visible") ||
		!strings.Contains(style, "--attribution-background: #231b16") || !strings.Contains(style, "--attribution-foreground: #fffefa") {
		t.Fatal("recovery page lacks the fixed responsive and light/dark styles")
	}
	digest := base64.StdEncoding.EncodeToString(crypto.Hash([]byte(style)))
	policy := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "style-src 'sha256-"+digest+"'") || strings.Contains(policy, "'unsafe-inline'") {
		t.Fatal("recovery policy does not pin the response stylesheet")
	}
}

type reassignedRecoveryHost struct{ fixtureBrandResolver }

func (f reassignedRecoveryHost) ForHost(ctx context.Context, _ string) (string, branding.Branding, error) {
	return f.fixtureBrandResolver.ForHost(ctx, "riverside.example")
}

func TestCustomerRecoveryUsesOnlyTheRegisteredHostBrand(t *testing.T) {
	previous := tenancy.CurrentQuarantine()
	quarantine := tenancy.NewQuarantine()
	tenancy.SetQuarantine(quarantine)
	t.Cleanup(func() { tenancy.SetQuarantine(previous) })
	for _, id := range []string{mappedBrandTenant, siblingBrandTenant} {
		quarantine.Enter(tenancy.QuarantineEntry{TenantID: id, Reason: tenancy.QuarantinePlaneMissing, Plane: "postgres"})
	}
	srv := testServer(fakePinger{}).WithCustomerBranding(fixtureBrandResolver{})
	srv.cfg.AuthMode = "sso"
	for _, tc := range []struct{ host, forwarded, customer, other string }{
		{"northstar.example", "riverside.example", "Northstar", "Riverside"},
		{"riverside.example", "northstar.example", "Riverside", "Northstar"},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/auth/login", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("X-Forwarded-Host", tc.forwarded)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body, "tenant_quarantined") ||
			!strings.Contains(body, "<bdi>"+tc.customer+"</bdi>") || strings.Contains(body, tc.other) ||
			!strings.Contains(body, `<a class="attribution" href="https://probectl.com">`) || !strings.Contains(body, `</svg> Powered by probectl</a>`) {
			t.Fatalf("%s recovery lost the correct brand or attribution: %d %s", tc.host, rec.Code, body)
		}
		if rec.Header().Get("Location") != "" || rec.Header().Get("Set-Cookie") != "" ||
			rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("%s recovery changed the authentication, caching or CSP policy: %v", tc.host, rec.Header())
		}
		assertFixedRecoveryStyle(t, rec)
	}

	req := httptest.NewRequest(http.MethodGet, "https://northstar.example/auth/login?tenant="+siblingBrandTenant, nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "Riverside") {
		t.Fatalf("a sibling routing hint escaped its host boundary: %d %s", rec.Code, rec.Body)
	}

	srv.WithCustomerBranding(reassignedRecoveryHost{})
	req = httptest.NewRequest(http.MethodGet, "https://northstar.example/auth/login", nil)
	req.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body, "</svg> probectl") ||
		strings.Contains(body, "Riverside") || strings.Contains(body, "Northstar") {
		t.Fatalf("host ownership changed during sign-in, expected the default recovery: %d %s", rec.Code, body)
	}
}
