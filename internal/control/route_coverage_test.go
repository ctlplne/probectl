// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"os"
	"regexp"
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

// ARCH-013: the NON-/v1 mounted surfaces (auth, enroll, ingest, SCIM, metrics,
// branding, security.txt, ...) must each be either documented in the spec or in
// this explicit exclusion list. Scanning the router source means a NEW mounted
// surface that is neither documented nor excluded fails the test — no silent
// undocumented route.
func TestNonV1SurfacesDocumentedOrExcluded(t *testing.T) {
	documented := openapiPaths(t)

	// Surfaces deliberately excluded from the tenant-facing OpenAPI: operational
	// endpoints, standards-defined surfaces, and SCIM (RFC 7644, its own spec).
	excludedExact := map[string]bool{
		"/metrics":                  true, // Prometheus exposition, not REST
		"/version":                  true, // build metadata
		"/branding":                 true, // white-label asset endpoint
		"/.well-known/security.txt": true, // RFC 9116
		"/openapi.json":             true, // the spec itself
		"/ui/":                      true, // ARCH-004 embedded SPA (not a REST surface)
		"/{$}":                      true, // root redirect to /ui/
	}
	excludedPrefix := []string{
		"/scim/v2/",        // SCIM is RFC 7644, documented separately
		"/ingest/changes/", // signed CI/CD change webhooks (HMAC; docs/change.md)
		"/ingest/itsm/",    // signed ITSM webhooks (HMAC; docs/change.md)
		// ARCH-006: the provider/management plane is a separate privilege domain
		// (CLAUDE.md §3), mounted method-less as a sub-router and documented in
		// ee/provider/openapi.json — not in the tenant-facing spec.
		"/provider/",
	}

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	// ARCH-006: also catch HandleFunc and method-less mounts (e.g. the method-less
	// "/provider/" sub-router). The method prefix is optional so a future
	// method-less or HandleFunc mount cannot slip past the documentation gate.
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\("(?:[A-Z]+ )?(/[^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		path := m[1]
		if strings.HasPrefix(path, "/v1/") {
			continue // covered by TestEveryV1RouteIsDocumented
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
			t.Errorf("mounted surface %q is neither documented in openapi.json nor in the explicit exclusion list (ARCH-013)", path)
		}
	}
}

// ARCH-006: the mount-scanning regex must catch method-less Handle and
// HandleFunc mounts, not only the "VERB /path" form. A method-less or
// HandleFunc mount that escaped the regex would never be checked against the
// spec or the exclusion list — a silent undocumented surface.
func TestMountRegexCatchesMethodlessAndHandleFunc(t *testing.T) {
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\("(?:[A-Z]+ )?(/[^"]*)"`)
	fixture := `
		mux.Handle("GET /v1/tests", h)
		mux.Handle("/provider/", sub)            // method-less sub-router
		mux.HandleFunc("GET /{$}", root)          // HandleFunc form
		mux.HandleFunc("/legacy/", legacy)        // method-less HandleFunc
	`
	got := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(fixture, -1) {
		got[m[1]] = true
	}
	for _, want := range []string{"/v1/tests", "/provider/", "/{$}", "/legacy/"} {
		if !got[want] {
			t.Errorf("regex failed to match mounted surface %q (ARCH-006: method-less/HandleFunc mounts must be caught)", want)
		}
	}
}
