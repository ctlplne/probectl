// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

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
	for _, mismatch := range providerRouteSpecMismatches(providerRouteOps(routes()), providerSpecOps(t)) {
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
	routeOps := providerRouteOps(routes())
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
	for _, rt := range routes() {
		pattern := strings.NewReplacer("{id}", "x").Replace(rt.Pattern)
		req := newReq(rt.Method, pattern, nil)
		rec := doReq(h, req)
		if rec.Code == 404 && !strings.Contains(rec.Body.String(), "not_found") {
			t.Errorf("%s %s: not mounted (plain 404)", rt.Method, rt.Pattern)
		}
	}
}

// DPR-012: an integrator learns field names from the contract, so every
// POST/PUT/PATCH either declares a JSON request body whose schema resolves,
// or states explicitly (x-probectl-request-body) why it takes none.
func TestProviderOpenAPIDeclaresRequestBodies(t *testing.T) {
	var doc struct {
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(providerSpec, &doc); err != nil {
		t.Fatal(err)
	}
	for p, methods := range doc.Paths {
		for m, op := range methods {
			switch strings.ToUpper(m) {
			case "POST", "PUT", "PATCH":
			default:
				continue
			}
			label := strings.ToUpper(m) + " " + p
			if why, ok := op["x-probectl-request-body"].(string); ok {
				if !strings.HasPrefix(why, "none:") {
					t.Errorf("%s: x-probectl-request-body must start with \"none:\" and give the reason, got %q", label, why)
				}
				if _, both := op["requestBody"]; both {
					t.Errorf("%s: declares a requestBody AND x-probectl-request-body", label)
				}
				continue
			}
			body, ok := op["requestBody"].(map[string]any)
			if !ok {
				t.Errorf("%s: declares no requestBody and no x-probectl-request-body reason (DPR-012)", label)
				continue
			}
			content, _ := body["content"].(map[string]any)
			js, _ := content["application/json"].(map[string]any)
			schema, _ := js["schema"].(map[string]any)
			ref, _ := schema["$ref"].(string)
			if ref == "" {
				t.Errorf("%s: requestBody must carry application/json with a $ref schema", label)
				continue
			}
			const prefix = "#/components/schemas/"
			if _, ok := doc.Components.Schemas[strings.TrimPrefix(ref, prefix)]; !strings.HasPrefix(ref, prefix) || !ok {
				t.Errorf("%s: requestBody $ref %q does not resolve", label, ref)
			}
		}
	}
}
