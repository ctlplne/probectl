// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
)

//go:embed openapi.json
var providerSpec []byte

// TestProviderOpenAPIMatchesRoutes mirrors the core OpenAPI gate for the
// provider surface: the route table and the spec must match EXACTLY — no
// undocumented provider routes, no documented phantoms (CLAUDE.md §6).
func TestProviderOpenAPIMatchesRoutes(t *testing.T) {
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
	routeOps := map[string]bool{}
	for _, rt := range Routes() {
		routeOps[rt.Method+" "+rt.Pattern] = true
	}
	for op := range routeOps {
		if !specOps[op] {
			t.Errorf("undocumented provider route: %s", op)
		}
	}
	for op := range specOps {
		if !routeOps[op] {
			t.Errorf("documented phantom route: %s", op)
		}
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
