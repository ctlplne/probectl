package control

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOpenAPIMatchesRoutes upholds "no undocumented routes" (CLAUDE.md §6, §8):
// the registered /v1 routes must exactly equal the /v1 operations documented in
// openapi.json — neither an undocumented handler nor a documented-but-missing
// route may exist. The route table (apiRoutes) is the single source of truth.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	registered := map[string]bool{}
	for _, rt := range testServer(nil).apiRoutes() {
		registered[rt.Method+" "+rt.Pattern] = true
	}

	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	verbs := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		for verb := range ops {
			if verbs[verb] {
				documented[strings.ToUpper(verb)+" "+path] = true
			}
		}
	}

	for r := range registered {
		if !documented[r] {
			t.Errorf("route %q is registered but not documented in openapi.json", r)
		}
	}
	for d := range documented {
		if !registered[d] {
			t.Errorf("operation %q is documented but has no registered route", d)
		}
	}
}
