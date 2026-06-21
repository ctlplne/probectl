// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

//go:embed openapi.json
var providerSpec []byte

// TestProviderOpenAPIMatchesRoutes mirrors the core OpenAPI gate for the
// provider surface: the route table and the spec must match EXACTLY — no
// undocumented provider routes, no documented phantoms (CLAUDE.md §6).
func TestProviderOpenAPIMatchesRoutes(t *testing.T) {
	for _, mismatch := range providerRouteSpecMismatches(providerRouteOps(Routes()), providerSpecOps(t)) {
		t.Error(mismatch)
	}
}

func providerSpecOps(t *testing.T) map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(providerSpec, &doc); err != nil {
		t.Fatal(err)
	}
	specOps := map[string]bool{}
	for p, methods := range doc.Paths {
		for m := range methods {
			specOps[strings.ToUpper(m)+" "+p] = true
		}
	}
	return specOps
}

func providerRouteOps(routes []RouteDecl) map[string]bool {
	routeOps := map[string]bool{}
	for _, rt := range routes {
		routeOps[rt.Method+" "+rt.Pattern] = true
	}
	return routeOps
}

func providerRouteSpecMismatches(routeOps, specOps map[string]bool) []string {
	var mismatches []string
	for op := range routeOps {
		if !specOps[op] {
			mismatches = append(mismatches, "undocumented provider route: "+op)
		}
	}
	for op := range specOps {
		if !routeOps[op] {
			mismatches = append(mismatches, "documented phantom route: "+op)
		}
	}
	sort.Strings(mismatches)
	return mismatches
}

func TestProviderOpenAPIGateCatchesPlantedDrift(t *testing.T) {
	routeOps := providerRouteOps(Routes())
	specOps := providerSpecOps(t)
	routeOps["GET /provider/v1/__planted_route_drift"] = true
	specOps["POST /provider/v1/__planted_spec_drift"] = true

	joined := strings.Join(providerRouteSpecMismatches(routeOps, specOps), "\n")
	if !strings.Contains(joined, "undocumented provider route: GET /provider/v1/__planted_route_drift") {
		t.Fatalf("planted undocumented provider route drift was not detected:\n%s", joined)
	}
	if !strings.Contains(joined, "documented phantom route: POST /provider/v1/__planted_spec_drift") {
		t.Fatalf("planted provider spec phantom drift was not detected:\n%s", joined)
	}
}

// TestProviderRoutesAreRegistered asserts every declared route is actually
// mounted (a table entry without a handler would 404 silently).
func TestProviderRoutesAreRegistered(t *testing.T) {
	h := newTestHandler(t)
	for _, rt := range Routes() {
		pattern := strings.NewReplacer("{id}", "x").Replace(rt.Pattern)
		req := newReq(rt.Method, pattern, nil)
		rec := doReq(h, req)
		if rec.Code == 404 && !strings.Contains(rec.Body.String(), "not_found") {
			t.Errorf("%s %s: not mounted (plain 404)", rt.Method, rt.Pattern)
		}
	}
}
