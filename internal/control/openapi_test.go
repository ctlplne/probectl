// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

var openAPIVerbs = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}

type openAPIDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

func parseOpenAPIDoc(t *testing.T) openAPIDoc {
	t.Helper()
	var doc openAPIDoc
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	return doc
}

type lifecycleExtension struct {
	Stage        string `json:"stage"`
	DeprecatedAt string `json:"deprecated_at"`
	Sunset       string `json:"sunset"`
	LTSUntil     string `json:"lts_until"`
	Replacement  string `json:"replacement"`
	Policy       string `json:"policy"`
}

type openAPIOperation struct {
	Deprecated bool                `json:"deprecated"`
	Lifecycle  *lifecycleExtension `json:"x-probectl-lifecycle"`
}

func parseOperation(t *testing.T, raw json.RawMessage) openAPIOperation {
	t.Helper()
	var op openAPIOperation
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatalf("parse openapi operation: %v", err)
	}
	return op
}

// TestOpenAPIMatchesRoutes upholds "no undocumented routes" (CLAUDE.md §6, §8):
// the registered /v1 routes must exactly equal the /v1 operations documented in
// openapi.json — neither an undocumented handler nor a documented-but-missing
// route may exist. The route table (apiRoutes) is the single source of truth.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	registered := map[string]bool{}
	for _, rt := range testServer(nil).apiRoutes() {
		registered[rt.Method+" "+rt.Pattern] = true
	}

	doc := parseOpenAPIDoc(t)
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		for verb := range ops {
			if openAPIVerbs[verb] {
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
	doc := parseOpenAPIDoc(t)
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

// TestDeprecatedOperationsDeclareLifecycle: SCHEMA-005. Any deprecated OpenAPI
// operation must carry the probectl lifecycle extension with concrete dates and
// a replacement. This turns "we have /v1" into a machine-readable retirement
// contract rather than a prose-only promise.
func TestDeprecatedOperationsDeclareLifecycle(t *testing.T) {
	doc := parseOpenAPIDoc(t)
	deprecated := 0
	for path, ops := range doc.Paths {
		for verb, raw := range ops {
			if !openAPIVerbs[verb] {
				continue
			}
			op := parseOperation(t, raw)
			if !op.Deprecated {
				continue
			}
			deprecated++
			if op.Lifecycle == nil {
				t.Fatalf("%s %s is deprecated but has no x-probectl-lifecycle", strings.ToUpper(verb), path)
			}
			lc := *op.Lifecycle
			if lc.Stage != "deprecated" || lc.Replacement == "" || lc.Policy == "" {
				t.Fatalf("%s %s lifecycle is incomplete: %+v", strings.ToUpper(verb), path, lc)
			}
			runtime, ok := apiLifecycleFor(strings.ToUpper(verb), path)
			if !ok {
				t.Fatalf("%s %s is deprecated in OpenAPI but has no runtime lifecycle headers", strings.ToUpper(verb), path)
			}
			if lc.DeprecatedAt != runtime.DeprecatedAt || lc.Sunset != runtime.Sunset || lc.LTSUntil != runtime.LTSUntil ||
				lc.Replacement != runtime.ReplacementMethod+" "+runtime.ReplacementPath {
				t.Fatalf("%s %s OpenAPI lifecycle does not match runtime lifecycle: openapi=%+v runtime=%+v", strings.ToUpper(verb), path, lc, runtime)
			}
			deprecatedAt := parseLifecycleDate(t, lc.DeprecatedAt, "deprecated_at")
			sunset := parseLifecycleDate(t, lc.Sunset, "sunset")
			ltsUntil := parseLifecycleDate(t, lc.LTSUntil, "lts_until")
			if sunset.Before(deprecatedAt) || ltsUntil.Before(sunset) {
				t.Fatalf("%s %s lifecycle dates out of order: %+v", strings.ToUpper(verb), path, lc)
			}
		}
	}
	if deprecated == 0 {
		t.Fatal("no deprecated OpenAPI operations carry lifecycle metadata")
	}
}

func parseLifecycleDate(t *testing.T, value, field string) time.Time {
	t.Helper()
	out, err := time.Parse(apiLifecycleDateLayout, value)
	if err != nil {
		t.Fatalf("%s is not YYYY-MM-DD: %q", field, value)
	}
	return out
}

func TestDeprecatedRouteLifecycleHeaders(t *testing.T) {
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "oidc"}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), fakePinger{}, nil, nil, nil)
	rec := do(srv, http.MethodDelete, "/v1/agents/agent-1")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("deprecated unauthenticated route = %d, want 401", rec.Code)
	}
	if got, want := rec.Header().Get("Deprecation"), structuredDate(deleteAgentLifecycle.DeprecatedAt); got != want {
		t.Fatalf("Deprecation = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("Sunset"), httpDate(deleteAgentLifecycle.Sunset); got != want {
		t.Fatalf("Sunset = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("X-Probectl-API-Replacement"), deleteAgentLifecycle.ReplacementMethod+" "+deleteAgentLifecycle.ReplacementPath; got != want {
		t.Fatalf("replacement header = %q, want %q", got, want)
	}
	if got := rec.Header().Get("X-Probectl-API-LTS-Until"); got != deleteAgentLifecycle.LTSUntil {
		t.Fatalf("lts header = %q, want %q", got, deleteAgentLifecycle.LTSUntil)
	}
	link := strings.Join(rec.Header().Values("Link"), ",")
	if !strings.Contains(link, `rel="successor-version"`) || !strings.Contains(link, "/openapi.json") {
		t.Fatalf("Link headers missing successor/openapi lifecycle entries: %q", link)
	}
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
			if docType != "number" || rt != "integer" {
				t.Errorf("field %q: handler emits JSON %s, openapi.json documents %s (SCHEMA-005 schema drift)", field, rt, docType)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no editions fields were type-checked — the fidelity guard is vacuous")
	}
}
