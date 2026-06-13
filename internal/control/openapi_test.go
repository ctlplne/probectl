// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"net/http"
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

// docResponseProps returns the documented {property: openapi-type} map for a
// GET operation's 200 application/json response (SCHEMA-005).
func docResponseProps(t *testing.T, path string) map[string]string {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	raw, ok := doc.Paths[path]["get"]
	if !ok {
		t.Fatalf("no GET %s in openapi.json", path)
	}
	var op struct {
		Responses map[string]struct {
			Content map[string]struct {
				Schema struct {
					Properties map[string]struct {
						Type string `json:"type"`
					} `json:"properties"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatalf("parse GET %s op: %v", path, err)
	}
	props := op.Responses["200"].Content["application/json"].Schema.Properties
	out := map[string]string{}
	for name, p := range props {
		out[name] = p.Type
	}
	if len(out) == 0 {
		t.Fatalf("GET %s documents no response properties", path)
	}
	return out
}

// jsonType maps a decoded JSON value to its OpenAPI type name.
func jsonType(v any) string {
	switch v.(type) {
	case bool:
		return "boolean"
	case float64:
		return "integer" // also matches "number"; editions uses integer
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// TestOpenAPIResponseSchemaFidelity: SCHEMA-005. Beyond route presence, the
// actual handler response must match the documented response SCHEMA. This
// validates GET /v1/editions field-by-field against openapi.json: a documented
// field whose type was mutated in the spec (without touching the handler) — or a
// handler field whose type drifted from the spec — reddens this test. Dependency-
// free (no JSON-Schema library), so it adds no external dependency.
func TestOpenAPIResponseSchemaFidelity(t *testing.T) {
	want := docResponseProps(t, "/v1/editions")

	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/editions")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/editions = %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode editions response: %v", err)
	}

	checked := 0
	for field, docType := range want {
		v, present := got[field]
		// Optional fields (omitempty) may be absent on the community/unlicensed
		// truth; SCHEMA-005 asserts TYPE FIDELITY for the fields that ARE present.
		if !present || v == nil {
			continue
		}
		if rt := jsonType(v); rt != docType {
			// "number" and "integer" are both float64 at runtime; treat as compatible.
			if !(docType == "number" && rt == "integer") {
				t.Errorf("field %q: handler emits JSON %s, openapi.json documents %s (SCHEMA-005 schema drift)", field, rt, docType)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no editions fields were type-checked — the fidelity guard is vacuous")
	}
}
