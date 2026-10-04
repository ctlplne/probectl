// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// openapiPaths loads the documented path set from the shipped spec.
func openapiPaths(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	set := map[string]bool{}
	for p := range spec.Paths {
		set[p] = true
	}
	return set
}

// nonV1ExcludedExact and nonV1ExcludedPrefix are the single reasoned allowlist of
// served non-/v1 surfaces intentionally absent from the tenant-facing OpenAPI:
// operational endpoints, standards-defined surfaces, SCIM (RFC 7644, its own spec),
// and the provider plane (ee/provider/openapi.json, a separate privilege domain —
// ARCH-006). Shared by TestNonV1SurfacesDocumentedOrExcluded and the non-/v1 half
// of TestOpenAPIMatchesRoutes (INV-04) so the two gates cannot drift apart. Adding
// an entry here is the deliberate, reviewed act of excluding a surface from the
// published spec — never a way to silence a genuinely undocumented route. (ARCH-013)
var nonV1ExcludedExact = map[string]bool{
	"/metrics":                  true, // Prometheus exposition, not REST
	"/version":                  true, // build metadata
	"/.well-known/security.txt": true, // RFC 9116
	"/openapi.json":             true, // the spec itself
	"/ui/":                      true, // ARCH-004 embedded SPA (not a REST surface)
	"/{$}":                      true, // root redirect to /ui/
}

var nonV1ExcludedPrefix = []string{
	"/scim/v2/",        // SCIM is RFC 7644, documented separately
	"/ingest/changes/", // signed CI/CD change webhooks (HMAC; docs/change.md)
	"/ingest/itsm/",    // signed ITSM webhooks (HMAC; docs/change.md)
	// ARCH-006: the provider/management plane is a separate privilege domain
	// (docs/architecture.md), mounted method-less as a sub-router and documented in
	// ee/provider/openapi.json — not in the tenant-facing spec.
	"/provider/",
}

// mountRe matches every router mount — mux.Handle / mux.HandleFunc with an optional
// "VERB " method prefix — capturing the method (group 1, empty for a method-less
// sub-router mount) and the path (group 2). ARCH-006: the method prefix is optional
// so a method-less or HandleFunc mount cannot slip past the documentation gate.
var mountRe = regexp.MustCompile(`mux\.Handle(?:Func)?\("(?:([A-Z]+) )?(/[^"]*)"`)

// servedNonV1Surfaces scans the router source for every mounted NON-/v1 surface,
// returning each as "METHOD /path" (or "/path" for a method-less mount). The /v1
// surface is owned by the exact parity check in TestOpenAPIMatchesRoutes, so it is
// excluded here. Scanning the source means a NEW mounted surface is seen the moment
// it is added, with no registration step to forget.
func servedNonV1Surfaces(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	var out []string
	for _, m := range mountRe.FindAllStringSubmatch(string(src), -1) {
		method, path := m[1], m[2]
		if strings.HasPrefix(path, "/v1/") {
			continue
		}
		if method == "" {
			out = append(out, path)
		} else {
			out = append(out, method+" "+path)
		}
	}
	return out
}

// undocumentedServedSurfaces returns the served surfaces ("METHOD /path" or "/path")
// whose PATH is neither documented in a published spec nor covered by the reasoned
// allowlist — the non-/v1 half of "no undocumented routes" (CONTRIBUTING.md; INV-04 /
// ARCH-013). It is the single checker both non-/v1 gates run, so a planted
// undocumented surface is caught identically by each. Any /v1 surface is skipped:
// those are owned by the exact bidirectional parity check.
func undocumentedServedSurfaces(served []string, documented, excludedExact map[string]bool, excludedPrefix []string) []string {
	var out []string
	for _, s := range served {
		path := s
		if i := strings.IndexByte(s, ' '); i >= 0 {
			path = s[i+1:]
		}
		if strings.HasPrefix(path, "/v1/") {
			continue
		}
		if documented[path] || excludedExact[path] {
			continue
		}
		excluded := false
		for _, p := range excludedPrefix {
			if strings.HasPrefix(path, p) {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ARCH-013: every versioned (/v1) route the server mounts MUST be documented in
// the OpenAPI spec. A new handler added to the route table without a spec entry
// fails here (convention §6: spec updated in the same change as the handler).
func TestEveryV1RouteIsDocumented(t *testing.T) {
	documented := openapiPaths(t)
	for _, r := range (&Server{}).apiRoutes() {
		if !strings.HasPrefix(r.Pattern, "/v1/") {
			continue
		}
		if !documented[r.Pattern] {
			t.Errorf("route %s %s is not in openapi.json (undocumented surface)", r.Method, r.Pattern)
		}
	}
}

// ARCH-004: apiRoutes is the single route ledger, so each ledger row must be a
// unique, versioned, permission-bearing operation with a real handler. This
// complements OpenAPI parity: parity catches doc drift, while this catches
// duplicate entries and accidental permissionless routes before they collapse
// into the parity test's map key.
func TestAPIRouteTableEntriesAreUniqueAndPermissioned(t *testing.T) {
	validMethods := map[string]bool{
		http.MethodDelete: true,
		http.MethodGet:    true,
		http.MethodPatch:  true,
		http.MethodPost:   true,
		http.MethodPut:    true,
	}
	permissionOptional := map[string]bool{
		"GET /v1/me": true,
	}
	seen := map[string]bool{}
	for _, r := range (&Server{}).apiRoutes() {
		key := r.Method + " " + r.Pattern
		if seen[key] {
			t.Errorf("duplicate apiRoute entry %q", key)
		}
		seen[key] = true
		if !validMethods[r.Method] {
			t.Errorf("route %q uses unsupported HTTP method %q", key, r.Method)
		}
		if !strings.HasPrefix(r.Pattern, "/v1/") {
			t.Errorf("route %q is not versioned under /v1/", key)
		}
		if r.Handler == nil {
			t.Errorf("route %q has nil handler", key)
		}
		if r.Permission == "" && !permissionOptional[key] {
			t.Errorf("route %q has no permission; only /v1/me is intentionally authenticated-without-specific-permission", key)
		}
	}
	for key := range permissionOptional {
		if !seen[key] {
			t.Errorf("permission-optional allowlist entry %q is stale", key)
		}
	}
}

// ARCH-013: the NON-/v1 mounted surfaces (auth, enroll, ingest, SCIM, metrics,
// deployment theming, security.txt, ...) must each be either documented in the spec or in
// this explicit exclusion list. Scanning the router source means a NEW mounted
// surface that is neither documented nor excluded fails the test — no silent
// undocumented route.
func TestNonV1SurfacesDocumentedOrExcluded(t *testing.T) {
	documented := openapiPaths(t)
	for _, undoc := range undocumentedServedSurfaces(servedNonV1Surfaces(t), documented, nonV1ExcludedExact, nonV1ExcludedPrefix) {
		t.Errorf("mounted surface %q is neither documented in openapi.json nor in the explicit exclusion list (ARCH-013)", undoc)
	}
}

// ARCH-006: the mount-scanning regex must catch method-less Handle and
// HandleFunc mounts, not only the "VERB /path" form. A method-less or
// HandleFunc mount that escaped the regex would never be checked against the
// spec or the exclusion list — a silent undocumented surface.
func TestMountRegexCatchesMethodlessAndHandleFunc(t *testing.T) {
	fixture := `
		mux.Handle("GET /v1/tests", h)
		mux.Handle("/provider/", sub)            // method-less sub-router
		mux.HandleFunc("GET /{$}", root)          // HandleFunc form
		mux.HandleFunc("/legacy/", legacy)        // method-less HandleFunc
	`
	got := map[string]bool{}
	for _, m := range mountRe.FindAllStringSubmatch(fixture, -1) {
		got[m[2]] = true // group 2 is the path (group 1 is the optional method)
	}
	for _, want := range []string{"/v1/tests", "/provider/", "/{$}", "/legacy/"} {
		if !got[want] {
			t.Errorf("regex failed to match mounted surface %q (ARCH-006: method-less/HandleFunc mounts must be caught)", want)
		}
	}
}
