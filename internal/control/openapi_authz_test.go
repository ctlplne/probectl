// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// AUTHZ-34. openapi.json has to declare HOW the API is authenticated and, per
// operation, WHICH permission the caller must hold — otherwise generated SDKs,
// API gateways, and human reviewers see every endpoint as unauthenticated and
// unauthorized. This gate loads the spec AND the v1.go route table (the single
// source of truth for the per-operation permission) and asserts parity:
//
//   - components.securitySchemes defines cookieAuth (the session cookie) and
//     bearerAuth (the API/MCP token), and a non-empty global `security`
//     requirement references only defined schemes;
//   - every registered /v1 operation is SECURED (its own non-empty `security`,
//     or — with no per-operation override — the global requirement), and none is
//     marked public (`security: []`);
//   - every /v1 operation carries x-required-permission equal to its v1.go
//     permission; the one authenticated-but-unprivileged route (/v1/me, empty
//     permission) carries none;
//   - the genuinely public, pre-identity / credential-less routes DO override
//     with an explicit `security: []`; and
//   - the dev-only X-Probectl-Tenant parameter, if present, is flagged
//     x-probectl-dev-only so it can never silently read as an identity input.
//
// publicSecurityOverrides is the curated set of non-/v1 surfaces that accept
// neither the session cookie nor an API token (SSO bootstrap, agent enrollment,
// the credential-less RUM beacon, health/version) and therefore declare an
// explicit empty `security`. It mirrors scripts' PUBLIC_ROUTES and the mux in
// server.go routes().
var publicSecurityOverrides = map[string]bool{
	"GET /healthz":              true,
	"GET /readyz":               true,
	"GET /version":              true,
	"GET /branding":             true,
	"GET /auth/login":           true,
	"GET /auth/callback":        true,
	"POST /auth/logout":         true,
	"POST /enroll/agent":        true,
	"POST /enroll/agent/rotate": true,
	"POST /ingest/rum":          true,
}

func decodeOpenAPISpec(t *testing.T) map[string]any {
	t.Helper()
	var spec map[string]any
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	return spec
}

func specOperation(spec map[string]any, method, path string) (map[string]any, bool) {
	paths, _ := spec["paths"].(map[string]any)
	item, _ := paths[path].(map[string]any)
	op, ok := item[strings.ToLower(method)].(map[string]any)
	return op, ok
}

// effectiveSecurity returns the operation's security requirement list, honoring
// OpenAPI inheritance: an operation that declares its own `security` overrides
// the root requirement; otherwise the root requirement applies.
func effectiveSecurity(spec, op map[string]any) ([]any, bool) {
	if sec, ok := op["security"]; ok {
		list, _ := sec.([]any)
		return list, true // explicitly set (possibly empty = public)
	}
	root, _ := spec["security"].([]any)
	return root, false
}

// securityModelMismatches is the production checker the gate runs. It is pure
// over a decoded spec so the planted-defect test can mutate a copy and prove the
// gate bites. A clean spec returns no mismatches.
func securityModelMismatches(spec map[string]any, routes []apiRoute, public map[string]bool) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	components, _ := spec["components"].(map[string]any)
	schemes, _ := components["securitySchemes"].(map[string]any)
	for _, want := range []string{"cookieAuth", "bearerAuth"} {
		if _, ok := schemes[want].(map[string]any); !ok {
			add("components.securitySchemes is missing %q", want)
		}
	}

	root, _ := spec["security"].([]any)
	if len(root) == 0 {
		add("root security requirement is absent or empty (no global auth)")
	}
	for _, req := range root {
		m, _ := req.(map[string]any)
		for scheme := range m {
			if _, ok := schemes[scheme].(map[string]any); !ok {
				add("root security references undefined scheme %q", scheme)
			}
		}
	}

	// TenantHeader, if it survives in the shipped spec, must be flagged dev-only.
	if params, ok := components["parameters"].(map[string]any); ok {
		if th, ok := params["TenantHeader"].(map[string]any); ok {
			if th["x-probectl-dev-only"] != true {
				add("components.parameters.TenantHeader must be marked x-probectl-dev-only: true")
			}
		}
	}

	for _, rt := range routes {
		id := rt.Method + " " + rt.Pattern
		op, ok := specOperation(spec, rt.Method, rt.Pattern)
		if !ok {
			add("route %q has no documented operation", id)
			continue
		}
		sec, _ := effectiveSecurity(spec, op)
		if len(sec) == 0 {
			add("operation %q is not secured (no effective security requirement)", id)
		}
		xrp, hasXRP := op["x-required-permission"].(string)
		switch {
		case rt.Permission == "":
			if hasXRP && xrp != "" {
				add("operation %q is authenticated-only but declares x-required-permission %q", id, xrp)
			}
		case !hasXRP:
			add("operation %q is missing x-required-permission (want %q)", id, rt.Permission)
		case xrp != rt.Permission:
			add("operation %q x-required-permission = %q, want %q", id, xrp, rt.Permission)
		}
	}

	for id := range public {
		parts := strings.SplitN(id, " ", 2)
		op, ok := specOperation(spec, parts[0], parts[1])
		if !ok {
			continue
		}
		sec, explicit := effectiveSecurity(spec, op)
		if !explicit || len(sec) != 0 {
			add("public route %q must declare an explicit empty security ([])", id)
		}
	}

	sort.Strings(out)
	return out
}

func TestOpenAPISecurityModelMatchesRoutes(t *testing.T) {
	spec := decodeOpenAPISpec(t)
	routes := testServer(nil).apiRoutes()
	for _, m := range securityModelMismatches(spec, routes, publicSecurityOverrides) {
		t.Error(m)
	}
}

// TestOpenAPISecurityGateCatchesPlantedDefects is the fail-on-old/pass-on-new
// proof. The live spec is clean under the SAME checker the gate runs; a spec
// missing its global auth, an operation forced public, a wrong x-required-
// permission, and a missing x-required-permission are each flagged. Reverting
// the openapi.json fix (securitySchemes absent, 0 ops with security) reddens
// TestOpenAPISecurityModelMatchesRoutes directly.
func TestOpenAPISecurityGateCatchesPlantedDefects(t *testing.T) {
	routes := testServer(nil).apiRoutes()

	if got := securityModelMismatches(decodeOpenAPISpec(t), routes, publicSecurityOverrides); len(got) != 0 {
		t.Fatalf("live spec is not clean under the security checker: %v", got)
	}

	// Defect 1: strip the global auth entirely — every /v1 op becomes unsecured.
	noAuth := decodeOpenAPISpec(t)
	delete(noAuth, "security")
	delete(noAuth["components"].(map[string]any), "securitySchemes")
	joined := strings.Join(securityModelMismatches(noAuth, routes, publicSecurityOverrides), "\n")
	if !strings.Contains(joined, "root security requirement is absent") ||
		!strings.Contains(joined, "securitySchemes is missing") ||
		!strings.Contains(joined, "is not secured") {
		t.Fatalf("stripped-auth defect not detected:\n%s", joined)
	}

	// Defect 2: force GET /v1/tests public (security: []) — a /v1 route may not be.
	forcedPublic := decodeOpenAPISpec(t)
	op, _ := specOperation(forcedPublic, "GET", "/v1/tests")
	op["security"] = []any{}
	if joined := strings.Join(securityModelMismatches(forcedPublic, routes, publicSecurityOverrides), "\n"); !strings.Contains(joined, `operation "GET /v1/tests" is not secured`) {
		t.Fatalf("forced-public defect not detected:\n%s", joined)
	}

	// Defect 3: a wrong x-required-permission on GET /v1/agents.
	wrongPerm := decodeOpenAPISpec(t)
	op, _ = specOperation(wrongPerm, "GET", "/v1/agents")
	op["x-required-permission"] = "tenant.admin"
	if joined := strings.Join(securityModelMismatches(wrongPerm, routes, publicSecurityOverrides), "\n"); !strings.Contains(joined, `operation "GET /v1/agents" x-required-permission = "tenant.admin", want "agent.read"`) {
		t.Fatalf("wrong-permission defect not detected:\n%s", joined)
	}

	// Defect 4: a missing x-required-permission on GET /v1/alerts.
	missingPerm := decodeOpenAPISpec(t)
	op, _ = specOperation(missingPerm, "GET", "/v1/alerts")
	delete(op, "x-required-permission")
	if joined := strings.Join(securityModelMismatches(missingPerm, routes, publicSecurityOverrides), "\n"); !strings.Contains(joined, `operation "GET /v1/alerts" is missing x-required-permission`) {
		t.Fatalf("missing-permission defect not detected:\n%s", joined)
	}
}
