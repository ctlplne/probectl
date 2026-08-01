// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// routesExemptFromDenialCoverage are /v1 routes that declare NO permission —
// authenticated-only surfaces where there is no permission to withhold. Each
// carries the reason it is authorization-free.
var routesExemptFromDenialCoverage = map[string]string{
	"GET /v1/me": "identity echo for the authenticated caller; it exposes only that caller's own principal",
}

// routesWithDedicatedDenialTests are capability-gated routes that answer 404
// when their capability is unwired (hiding existence deliberately), so the
// generic harness cannot reach their authorization layer. Each names the test
// that DOES prove refusal, so the coverage claim stays true rather than
// quietly shrinking.
var routesWithDedicatedDenialTests = map[string]string{
	"POST /v1/audit/ir/{event_ref}/reveal": "IR reveal answers 404 until an investigator capability is mounted; " +
		"denial is proven with the capability wired in irattribution_test.go " +
		"(rbac_denied and abac_denied cases assert 403 with the audited reason)",
}

// TestEveryRouteRefusesAnUnderPrivilegedPrincipal is the S-e0e73b57 coverage
// rule. The shared dev test principal holds EVERY permission, which made
// requirePermission a pass-through for the handler suites: about forty suites
// nominally traversed it and only a handful ever observed a refusal. The lane
// that produced nine authorization-bypass findings was the lane the tests
// exercised least.
//
// Rather than asking 122 files to each remember a negative case, this test
// DERIVES the coverage from the route table: for every route, it issues the
// request with the route's own permission withheld and requires a refusal.
// A new route is covered the moment it is registered — the coverage cannot
// drift from the table because it IS the table.
func TestEveryRouteRefusesAnUnderPrivilegedPrincipal(t *testing.T) {
	srv := testServer(fakePinger{})
	handler := srv.Handler()

	var uncovered []string
	seenExempt := map[string]bool{}
	for _, rt := range srv.apiRoutes() {
		key := rt.Method + " " + rt.Pattern
		if _, exempt := routesExemptFromDenialCoverage[key]; exempt {
			seenExempt[key] = true
			if rt.Permission != "" {
				t.Errorf("%s is listed as authorization-free but declares permission %q", key, rt.Permission)
			}
			continue
		}
		if _, dedicated := routesWithDedicatedDenialTests[key]; dedicated {
			seenExempt[key] = true
			continue
		}
		if rt.Permission == "" {
			uncovered = append(uncovered, key+" (declares no permission and is not classified as authorization-free)")
			continue
		}

		req := httptest.NewRequest(rt.Method, concretePath(rt.Pattern), strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(testWithholdPermissionsHeader, rt.Permission)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// The route must refuse. 403 is the expected shape; 401 is also a
		// refusal. Anything else means the caller reached the handler without
		// the permission the table says it needs.
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			uncovered = append(uncovered, key+" returned "+http.StatusText(rec.Code)+
				" without permission "+rt.Permission)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("routes that did NOT refuse an under-privileged principal:\n  %s", strings.Join(uncovered, "\n  "))
	}

	var stale []string
	for key := range routesExemptFromDenialCoverage {
		if !seenExempt[key] {
			stale = append(stale, key)
		}
	}
	for key := range routesWithDedicatedDenialTests {
		if !seenExempt[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("stale authorization-free classifications (no such route): %s", strings.Join(stale, ", "))
	}
}

// concretePath substitutes a syntactically valid value for each {param} so the
// request routes to the handler rather than 404-ing before authorization runs.
func concretePath(pattern string) string {
	out := pattern
	for {
		open := strings.Index(out, "{")
		if open < 0 {
			break
		}
		end := strings.Index(out[open:], "}")
		if end < 0 {
			break
		}
		name := out[open+1 : open+end]
		value := "10000000-0000-4000-8000-000000000001"
		switch {
		case strings.Contains(name, "fingerprint"):
			value = "fp-test"
		case strings.Contains(name, "slug"), strings.Contains(name, "name"), strings.Contains(name, "key"):
			value = "test"
		}
		out = out[:open] + value + out[open+end+1:]
	}
	return out
}

// TestRouteDenialCoverageCanFail is the anti-vacuous half: the harness must
// actually observe a refusal, so a route whose permission is NOT withheld
// reaches its handler and returns something other than 403/401. If this ever
// stops holding, the coverage test above would pass no matter what the
// middleware did.
func TestRouteDenialCoverageCanFail(t *testing.T) {
	srv := testServer(fakePinger{})
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req) // full permissions: must NOT be refused
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("a fully-privileged principal was refused (%d) — the withhold harness is inverted", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	req.Header.Set(testWithholdPermissionsHeader, permTestRead)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("withholding %s did not produce a refusal (got %d) — the harness cannot observe denial", permTestRead, rec.Code)
	}
}
