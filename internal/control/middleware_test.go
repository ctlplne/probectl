package control

import (
	"net/http"
	"strings"
	"testing"
)

// U-023 smoke test: every UI/API response carries the strict CSP and the
// anti-framing headers — the policy is set in the outermost middleware, so a
// public route, a /v1 route (even its 401), and an unknown path all get it.
func TestSecurityHeadersCSPAndFraming(t *testing.T) {
	srv := testServer(fakePinger{})
	for _, path := range []string{"/healthz", "/v1/tests", "/v1/me", "/does-not-exist"} {
		rec := do(srv, http.MethodGet, path)

		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("%s: missing Content-Security-Policy", path)
		}
		for _, directive := range []string{
			"default-src 'self'",
			"script-src 'self'",
			"frame-ancestors 'none'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s: CSP missing %q (got %q)", path, directive, csp)
			}
		}
		// Strict means strict: no inline allowances and no nonce needed — the
		// bundle is fully same-origin external assets (guardrail 11/12).
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP must not allow inline/eval (got %q)", path, csp)
		}

		if xfo := rec.Header().Get("X-Frame-Options"); xfo != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, xfo)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", path)
		}
		// SEC-006: referrer + permissions policy on every response.
		if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, rp)
		}
		pp := rec.Header().Get("Permissions-Policy")
		if pp == "" {
			t.Fatalf("%s: missing Permissions-Policy", path)
		}
		for _, feature := range []string{"camera=()", "microphone=()", "geolocation=()", "interest-cohort=()"} {
			if !strings.Contains(pp, feature) {
				t.Errorf("%s: Permissions-Policy missing %q (got %q)", path, feature, pp)
			}
		}
	}
}
