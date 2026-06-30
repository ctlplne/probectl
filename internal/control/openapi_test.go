// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
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

type paginationExtension struct {
	Mode        string `json:"mode"`
	CursorParam string `json:"cursor_param"`
	LimitParam  string `json:"limit_param"`
	NextCursor  string `json:"next_cursor"`
	MaxLimit    int    `json:"max_limit"`
	MaxItems    int    `json:"max_items"`
	Reason      string `json:"reason"`
}

type openAPIParameter struct {
	Ref      string `json:"$ref"`
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Schema   struct {
		Type    openAPIType `json:"type"`
		Minimum float64     `json:"minimum"`
		Maximum float64     `json:"maximum"`
		Default float64     `json:"default"`
	} `json:"schema"`
}

type openAPISchema struct {
	Ref        string                   `json:"$ref"`
	Type       any                      `json:"type"`
	Enum       []string                 `json:"enum"`
	Properties map[string]openAPISchema `json:"properties"`
}

type openAPIResponse struct {
	Content map[string]struct {
		Schema openAPISchema `json:"schema"`
	} `json:"content"`
}

type openAPIType string

func (typ *openAPIType) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*typ = openAPIType(single)
		return nil
	}
	var union []string
	if err := json.Unmarshal(data, &union); err != nil {
		return err
	}
	for _, item := range union {
		if item != "null" {
			*typ = openAPIType(item)
			return nil
		}
	}
	*typ = ""
	return nil
}

type openAPIOperation struct {
	OperationID string                     `json:"operationId"`
	Deprecated  bool                       `json:"deprecated"`
	Lifecycle   *lifecycleExtension        `json:"x-probectl-lifecycle"`
	Pagination  *paginationExtension       `json:"x-probectl-pagination"`
	Parameters  []openAPIParameter         `json:"parameters"`
	Responses   map[string]openAPIResponse `json:"responses"`
}

func parseOperation(t *testing.T, raw json.RawMessage) openAPIOperation {
	t.Helper()
	var op openAPIOperation
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatalf("parse openapi operation: %v", err)
	}
	return op
}

func TestOpenAPIErrorCodeRegistry(t *testing.T) {
	var spec struct {
		Components struct {
			Schemas map[string]openAPISchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	codeSchema, ok := spec.Components.Schemas["ErrorCode"]
	if !ok {
		t.Fatal("OpenAPI is missing components.schemas.ErrorCode")
	}
	if openAPISchemaType(codeSchema) != "string" {
		t.Fatalf("ErrorCode type = %v, want string", codeSchema.Type)
	}
	if got, want := codeSchema.Enum, apierror.RegisteredCodes(); !sameStrings(got, want) {
		t.Fatalf("ErrorCode enum drifted:\ngot  %v\nwant %v", got, want)
	}
	detailSchema := spec.Components.Schemas["ErrorDetail"]
	detailCodeRef := detailSchema.Properties["code"].Ref
	if detailCodeRef != "#/components/schemas/ErrorCode" {
		t.Fatalf("ErrorDetail.code ref = %q, want ErrorCode", detailCodeRef)
	}
	errorSchema := spec.Components.Schemas["Error"]
	detailRef := errorSchema.Properties["error"].Ref
	if detailRef != "#/components/schemas/ErrorDetail" {
		t.Fatalf("Error.error ref = %q, want ErrorDetail", detailRef)
	}
}

func openAPISchemaType(schema openAPISchema) string {
	switch t := schema.Type.(type) {
	case string:
		return t
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "null" {
				return s
			}
		}
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOpenAPITypeAcceptsNullableUnion(t *testing.T) {
	var schema struct {
		Type openAPIType `json:"type"`
	}
	if err := json.Unmarshal([]byte(`{"type":["string","null"]}`), &schema); err != nil {
		t.Fatalf("parse nullable union type: %v", err)
	}
	if schema.Type != "string" {
		t.Fatalf("nullable union type = %q, want string", schema.Type)
	}
}

// TestOpenAPIMatchesRoutes upholds "no undocumented routes" (CLAUDE.md §6, §8):
// the registered /v1 routes must exactly equal the /v1 operations documented in
// openapi.json — neither an undocumented handler nor a documented-but-missing
// route may exist. The route table (apiRoutes) is the single source of truth.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	for _, mismatch := range routeSpecMismatches(registeredRouteOps(testServer(nil).apiRoutes()), documentedV1Ops(t)) {
		t.Error(mismatch)
	}
}

func registeredRouteOps(routes []apiRoute) map[string]bool {
	registered := map[string]bool{}
	for _, rt := range routes {
		registered[rt.Method+" "+rt.Pattern] = true
	}
	return registered
}

func documentedV1Ops(t *testing.T) map[string]bool {
	t.Helper()
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
	return documented
}

func routeSpecMismatches(registered, documented map[string]bool) []string {
	var mismatches []string
	for r := range registered {
		if !documented[r] {
			mismatches = append(mismatches, fmt.Sprintf("route %q is registered but not documented in openapi.json", r))
		}
	}
	for d := range documented {
		if !registered[d] {
			mismatches = append(mismatches, fmt.Sprintf("operation %q is documented but has no registered route", d))
		}
	}
	sort.Strings(mismatches)
	return mismatches
}

func TestOpenAPIGateCatchesPlantedRouteAndSpecDrift(t *testing.T) {
	registered := registeredRouteOps(testServer(nil).apiRoutes())
	documented := documentedV1Ops(t)
	registered["GET /v1/__planted_route_drift"] = true
	documented["POST /v1/__planted_spec_drift"] = true

	joined := strings.Join(routeSpecMismatches(registered, documented), "\n")
	if !strings.Contains(joined, `route "GET /v1/__planted_route_drift" is registered but not documented`) {
		t.Fatalf("planted undocumented route drift was not detected:\n%s", joined)
	}
	if !strings.Contains(joined, `operation "POST /v1/__planted_spec_drift" is documented but has no registered route`) {
		t.Fatalf("planted documented phantom drift was not detected:\n%s", joined)
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

func TestOpenAPIAgentPaginationContract(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type        openAPIType `json:"type"`
					Description string      `json:"description"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}

	var op struct {
		Parameters []struct {
			Ref         string `json:"$ref"`
			Name        string `json:"name"`
			In          string `json:"in"`
			Description string `json:"description"`
			Schema      struct {
				Type    openAPIType `json:"type"`
				Minimum float64     `json:"minimum"`
				Maximum float64     `json:"maximum"`
				Default float64     `json:"default"`
			} `json:"schema"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(spec.Paths["/v1/agents"]["get"], &op); err != nil {
		t.Fatalf("parse GET /v1/agents operation: %v", err)
	}

	params := map[string]struct {
		In          string
		Type        openAPIType
		Description string
		Minimum     float64
		Maximum     float64
		Default     float64
	}{}
	for _, p := range op.Parameters {
		if p.Name == "" {
			continue // TenantHeader is a shared $ref.
		}
		params[p.Name] = struct {
			In          string
			Type        openAPIType
			Description string
			Minimum     float64
			Maximum     float64
			Default     float64
		}{In: p.In, Type: p.Schema.Type, Description: p.Description, Minimum: p.Schema.Minimum, Maximum: p.Schema.Maximum, Default: p.Schema.Default}
	}

	after, ok := params["after"]
	if !ok {
		t.Fatal("GET /v1/agents is missing after query parameter (UX-003)")
	}
	if after.In != "query" || after.Type != "string" || !strings.Contains(after.Description, "next_cursor") {
		t.Fatalf("GET /v1/agents after parameter drifted: %+v", after)
	}
	limit, ok := params["limit"]
	if !ok {
		t.Fatal("GET /v1/agents is missing limit query parameter (UX-003)")
	}
	if limit.In != "query" || limit.Type != "integer" || limit.Minimum != 1 || limit.Maximum != 1000 || limit.Default != 200 {
		t.Fatalf("GET /v1/agents limit parameter drifted: %+v", limit)
	}

	next, ok := spec.Components.Schemas["AgentList"].Properties["next_cursor"]
	if !ok {
		t.Fatal("AgentList is missing next_cursor (UX-003)")
	}
	if next.Type != "string" || !strings.Contains(next.Description, "SCALE-010") {
		t.Fatalf("AgentList.next_cursor drifted: %+v", next)
	}
}

func TestOpenAPIRolloutPathParameters(t *testing.T) {
	doc := parseOpenAPIDoc(t)
	cases := map[string]string{
		"/v1/rollouts/{id}":         "get",
		"/v1/rollouts/{id}/advance": "post",
		"/v1/rollouts/{id}/verify":  "post",
		"/v1/rollouts/{id}/halt":    "post",
		"/v1/rollouts/{id}/resume":  "post",
	}
	for path, method := range cases {
		raw := doc.Paths[path][method]
		op := parseOperation(t, raw)
		var found bool
		for _, p := range op.Parameters {
			if p.Name != "id" {
				continue
			}
			found = true
			if p.In != "path" || !p.Required || p.Schema.Type != "string" {
				t.Fatalf("%s %s id parameter = %+v, want required string path parameter", strings.ToUpper(method), path, p)
			}
		}
		if !found {
			t.Fatalf("%s %s is missing the rollout id path parameter", strings.ToUpper(method), path)
		}
	}
}

var collectionPaginationContracts = map[string]string{
	"/v1/tests":                  "cursor",
	"/v1/agents":                 "cursor",
	"/v1/audit":                  "cursor",
	"/v1/alerts":                 "bounded",
	"/v1/alerts/active":          "bounded",
	"/v1/incidents":              "bounded",
	"/v1/changes":                "bounded",
	"/v1/incidents/{id}/changes": "bounded",
	"/v1/abac/policies":          "bounded",
	"/v1/directory/scim-tokens":  "bounded",
	"/v1/flows/top":              "bounded",
	"/v1/flows/capacity":         "bounded",
	"/v1/flows/anomalies":        "bounded",
	"/v1/topology":               "bounded",
	"/v1/slos":                   "bounded",
	"/v1/outages":                "bounded",
	"/v1/rum":                    "bounded",
	"/v1/compliance":             "bounded",
	"/v1/tls/posture":            "bounded",
	"/v1/threat/detections":      "bounded",
	"/v1/endpoints":              "bounded",
	"/v1/results/latest":         "bounded",
	"/v1/otlp/traces":            "bounded",
	"/v1/otlp/logs":              "bounded",
	"/v1/otlp-tokens":            "bounded",
	"/v1/rollouts":               "bounded",
	"/v1/remediation/proposals":  "bounded",
}

// TestOpenAPICollectionPaginationContract is PRODUCT-009's guardrail. Every
// collection-like GET has to either expose the shared cursor shape or document a
// bounded snapshot/top-N contract with a hard item cap. That keeps high-cardinality
// telemetry views from becoming accidental unbounded dumps.
func TestOpenAPICollectionPaginationContract(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]openAPISchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}

	for path, wantMode := range collectionPaginationContracts {
		ops, ok := spec.Paths[path]
		if !ok {
			t.Fatalf("collection registry references missing path %s", path)
		}
		raw, ok := ops["get"]
		if !ok {
			t.Fatalf("collection registry references %s without GET operation", path)
		}
		op := parseOperation(t, raw)
		if op.Pagination == nil {
			t.Fatalf("GET %s is collection-like but lacks x-probectl-pagination", path)
		}
		pg := *op.Pagination
		if pg.Mode != wantMode {
			t.Fatalf("GET %s pagination mode = %q, want %q", path, pg.Mode, wantMode)
		}
		switch pg.Mode {
		case "cursor":
			assertCursorPagination(t, path, op, spec.Components.Schemas)
		case "bounded":
			assertBoundedPagination(t, path, op)
		default:
			t.Fatalf("GET %s has unknown pagination mode %q", path, pg.Mode)
		}
	}

	for path, ops := range spec.Paths {
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		raw, ok := ops["get"]
		if !ok {
			continue
		}
		op := parseOperation(t, raw)
		if op.Pagination == nil && strings.HasPrefix(op.OperationID, "list") {
			t.Errorf("GET %s (%s) is list-like but is missing from the collection pagination registry", path, op.OperationID)
		}
		if op.Pagination != nil {
			if _, ok := collectionPaginationContracts[path]; !ok {
				t.Errorf("GET %s declares x-probectl-pagination but is missing from the collection pagination registry", path)
			}
		}
	}
}

func assertCursorPagination(t *testing.T, path string, op openAPIOperation, schemas map[string]openAPISchema) {
	t.Helper()
	pg := *op.Pagination
	if pg.CursorParam == "" || pg.LimitParam == "" || pg.NextCursor == "" || pg.MaxLimit <= 0 {
		t.Fatalf("GET %s cursor pagination is incomplete: %+v", path, pg)
	}
	params := queryParams(op.Parameters)
	cursor, ok := params[pg.CursorParam]
	if !ok || cursor.In != "query" {
		t.Fatalf("GET %s cursor_param %q is not a query parameter", path, pg.CursorParam)
	}
	limit, ok := params[pg.LimitParam]
	if !ok || limit.In != "query" {
		t.Fatalf("GET %s limit_param %q is not a query parameter", path, pg.LimitParam)
	}
	if limit.Schema.Type != "integer" || limit.Schema.Minimum < 1 || int(limit.Schema.Maximum) != pg.MaxLimit {
		t.Fatalf("GET %s limit parameter must be integer min=1 max=%d, got %+v", path, pg.MaxLimit, limit.Schema)
	}
	schema := resolveSchema(responseSchema(t, path, op), schemas)
	if _, ok := schema.Properties[pg.NextCursor]; !ok {
		t.Fatalf("GET %s response schema is missing next cursor field %q", path, pg.NextCursor)
	}
}

func assertBoundedPagination(t *testing.T, path string, op openAPIOperation) {
	t.Helper()
	pg := *op.Pagination
	if pg.MaxItems <= 0 || strings.TrimSpace(pg.Reason) == "" {
		t.Fatalf("GET %s bounded pagination must declare max_items and reason: %+v", path, pg)
	}
	if pg.LimitParam == "" {
		return
	}
	limit, ok := queryParams(op.Parameters)[pg.LimitParam]
	if !ok || limit.In != "query" {
		t.Fatalf("GET %s limit_param %q is not a query parameter", path, pg.LimitParam)
	}
	if limit.Schema.Type != "integer" || limit.Schema.Minimum < 1 {
		t.Fatalf("GET %s bounded limit must be an integer with minimum 1, got %+v", path, limit.Schema)
	}
	if limit.Schema.Maximum > 0 && int(limit.Schema.Maximum) > pg.MaxItems {
		t.Fatalf("GET %s limit maximum %v exceeds documented max_items %d", path, limit.Schema.Maximum, pg.MaxItems)
	}
}

func queryParams(params []openAPIParameter) map[string]openAPIParameter {
	out := map[string]openAPIParameter{}
	for _, p := range params {
		if p.Name != "" && p.In == "query" {
			out[p.Name] = p
		}
	}
	return out
}

func responseSchema(t *testing.T, path string, op openAPIOperation) openAPISchema {
	t.Helper()
	resp, ok := op.Responses["200"]
	if !ok {
		t.Fatalf("GET %s has no 200 response", path)
	}
	content, ok := resp.Content["application/json"]
	if !ok {
		t.Fatalf("GET %s has no application/json 200 response", path)
	}
	return content.Schema
}

func resolveSchema(schema openAPISchema, schemas map[string]openAPISchema) openAPISchema {
	const prefix = "#/components/schemas/"
	if !strings.HasPrefix(schema.Ref, prefix) {
		return schema
	}
	name := strings.TrimPrefix(schema.Ref, prefix)
	if resolved, ok := schemas[name]; ok {
		return resolved
	}
	return schema
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
