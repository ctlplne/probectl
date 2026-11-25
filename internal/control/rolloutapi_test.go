// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/lifecycle"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestStagedEndpointPackageChecksExactDigest(t *testing.T) {
	const tenant = "10000000-0000-4000-8000-000000000001"
	const approved = "test installer data"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	objects, err := objectstore.ForTenant(objectstore.NewMemory(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	artifact := agent.VerifiedArtifact{
		Digest:   "sha256:" + hex.EncodeToString(crypto.Hash([]byte(approved))),
		Endpoint: &agent.EndpointArtifact{Platform: "darwin/arm64"},
	}
	for _, tt := range []struct {
		name string
		body string
		want apierror.Kind
	}{
		{name: "different bytes of the same size", body: strings.Repeat("x", len(approved)), want: apierror.KindConflict},
		{name: "empty installer", want: apierror.KindBadRequest},
		{name: "approved bytes", body: approved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := objects.Put(ctx, endpointPackagePath(artifact), "application/octet-stream", []byte(tt.body)); err != nil {
				t.Fatal(err)
			}
			stage, size, err := stageEndpointPackage(ctx, tenant, objects, artifact)
			if tt.want == 0 {
				if err != nil || stage == nil || size != int64(len(approved)) {
					t.Fatalf("approved installer staging = %v, %d, %v", stage != nil, size, err)
				}
				t.Cleanup(func() { _ = stage.Close() })
				return
			}
			domain, ok := apierror.As(err)
			if !ok || domain.Kind != tt.want || stage != nil || size != 0 {
				t.Fatalf("unapproved installer staging = %v, %d, %v", stage != nil, size, err)
			}
		})
	}
}

// OPS-002: the manager plans a rollout, steps it via the engine, and halt/
// resume gate advancement (the operator surface over the rollout state machine).
func TestRolloutManagerLifecycle(t *testing.T) {
	m := newRolloutManager()
	fleet := []agent.FleetAgent{
		{ID: "a1", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
		{ID: "a2", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
		{ID: "a3", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
	}
	art := agent.VerifiedArtifact{Version: "v0.2.0", Digest: "sha256:abababababababababababababababababababababababababababababababab", Method: "cosign verify", VerifiedBy: "op"}
	plan, err := agent.PlanRolloutAt(fleet, art, lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := m.put("t", plan)

	got, ok := m.get("t", id)
	if !ok || got != plan {
		t.Fatal("manager did not return the stored plan")
	}
	// Tenant isolation: another tenant can't see it.
	if _, ok := m.get("other", id); ok {
		t.Fatal("rollout leaked across tenants")
	}

	// Halt gates advancement; Resume clears it.
	plan.Halt("operator halt")
	if !plan.Halted {
		t.Fatal("Halt did not set Halted")
	}
	if _, err := plan.Advance(time.Now()); err == nil {
		t.Fatal("a halted rollout must refuse Advance")
	}
	if err := plan.Resume("remediated", time.Now()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if plan.Halted {
		t.Fatal("Resume did not clear the halt")
	}
}

func TestRolloutReasonRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/rollouts/r1/halt", http.NoBody)
	got, err := rolloutReason(r, "fallback reason")
	if err != nil {
		t.Fatalf("empty body should use fallback: %v", err)
	}
	if got != "fallback reason" {
		t.Fatalf("empty body reason = %q, want fallback", got)
	}

	r = httptest.NewRequest(http.MethodPost, "/v1/rollouts/r1/resume", strings.NewReader(`{"reason":" node replaced "}`))
	got, err = rolloutReason(r, "fallback reason")
	if err != nil {
		t.Fatalf("explicit reason: %v", err)
	}
	if got != "node replaced" {
		t.Fatalf("explicit reason = %q, want trimmed operator note", got)
	}

	r = httptest.NewRequest(http.MethodPost, "/v1/rollouts/r1/resume", strings.NewReader(`{"reason":" "}`))
	if _, err := rolloutReason(r, "fallback reason"); err == nil {
		t.Fatal("blank explicit reason must fail closed")
	}
}

func TestFleetRCERoutesDoNotAcceptAgentExecutablePayload(t *testing.T) {
	typ := reflect.TypeOf(rolloutCreateRequest{})
	got := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			got[name] = true
		}
	}
	want := map[string]bool{
		"version":        true,
		"digest":         true,
		"verify_method":  true,
		"canary_percent": true,
		"early_percent":  true,
		"endpoint":       true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rollout create JSON contract drifted:\ngot  %v\nwant %v", got, want)
	}
	wantEndpoint := []string{"platform", "executable_identity"}
	endpoint := reflect.TypeFor[rolloutEndpointConfiguration]()
	if endpoint.NumField() != len(wantEndpoint) {
		t.Fatalf("native rollout configuration has %d fields, want %d", endpoint.NumField(), len(wantEndpoint))
	}
	for i, name := range wantEndpoint {
		if field := endpoint.Field(i); field.Tag.Get("json") != name || field.Type.Kind() != reflect.String {
			t.Fatalf("native rollout field %d = %v, want %s string", i, field, name)
		}
	}

	forbidden := regexp.MustCompile(`(?i)"(image|image_tag|executable|binary|script|command|download_url|url)"\s*:`)
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &spec); err != nil {
		t.Fatalf("parse openapi: %v", err)
	}
	for path, ops := range spec.Paths {
		if !strings.HasPrefix(path, "/v1/agents") && !strings.HasPrefix(path, "/v1/rollouts") {
			continue
		}
		for method, raw := range ops {
			if !openAPIVerbs[method] {
				continue
			}
			var op struct {
				RequestBody json.RawMessage `json:"requestBody"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("parse operation for %s %s: %v", strings.ToUpper(method), path, err)
			}
			if len(op.RequestBody) == 0 {
				continue
			}
			if forbidden.Match(op.RequestBody) {
				t.Fatalf("%s %s accepts an agent executable/image/script mutation payload: %s", strings.ToUpper(method), path, op.RequestBody)
			}
		}
	}
}

func TestExpectedTenantAssertionContract(t *testing.T) {
	spec := decodeOpenAPISpec(t)
	components, _ := spec["components"].(map[string]any)
	parameters, _ := components["parameters"].(map[string]any)
	expected, _ := parameters["ExpectedRequestTenant"].(map[string]any)
	devOnly, _ := parameters["TenantHeader"].(map[string]any)
	if expected["name"] != "X-Probectl-Tenant" || expected["in"] != "header" ||
		expected["required"] != false || expected["x-probectl-dev-only"] == true || devOnly["x-probectl-dev-only"] != true {
		t.Fatal("the production tenant assertion and development-only override must be distinct optional headers")
	}
	for _, route := range testServer(fakePinger{}).apiRoutes() {
		assertsTenant := acceptsExpectedTenant(route.Pattern)
		op, _ := specOperation(spec, route.Method, route.Pattern)
		params, _ := op["parameters"].([]any)
		var assertions int
		for _, raw := range params {
			param, _ := raw.(map[string]any)
			if param["$ref"] == "#/components/parameters/ExpectedRequestTenant" {
				assertions++
			}
		}
		if (assertsTenant && assertions != 1) || (!assertsTenant && assertions != 0) {
			t.Errorf("%s %s documents %d tenant assertions", route.Method, route.Pattern, assertions)
		}
		if responses, _ := op["responses"].(map[string]any); assertsTenant && responses["403"] == nil {
			t.Errorf("%s %s omits the tenant assertion refusal response", route.Method, route.Pattern)
		}
	}
}

func TestFleetRolloutTenantHintRefusesAStaleSession(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.AuthMode = "sso"
	const first = "00000000-0000-4000-8000-000000000101"
	const second = "00000000-0000-4000-8000-000000000102"
	firstPlan := &agent.RolloutPlan{}
	secondPlan := &agent.RolloutPlan{}
	srv.rolloutMgr().remember(first, "same-id", firstPlan)
	srv.rolloutMgr().remember(second, "same-id", secondPlan)

	request := func(method, path, principalTenant string, expected ...string) int {
		r := httptest.NewRequest(method, path, http.NoBody)
		for _, value := range expected {
			r.Header.Add("X-Probectl-Tenant", value)
		}
		r = r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{
			TenantID: principalTenant, Permissions: map[string]bool{permAgentRead: true, permAgentWrite: true},
		}))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		return rec.Code
	}
	for _, path := range []string{"/v1/agents", "/v1/rollouts"} {
		if status := request(http.MethodGet, path, second, first); status != http.StatusForbidden {
			t.Fatalf("stale fleet read for %s returned %d, want 403", path, status)
		}
	}
	const halt = "/v1/rollouts/same-id/halt"
	if status := request(http.MethodPost, halt, second, first); status != http.StatusForbidden || firstPlan.Halted || secondPlan.Halted {
		t.Fatalf("stale confirmation returned %d and halt states are %t/%t", status, firstPlan.Halted, secondPlan.Halted)
	}
	if status := request(http.MethodPost, halt, second, second, first); status != http.StatusForbidden || firstPlan.Halted || secondPlan.Halted {
		t.Fatalf("ambiguous confirmation returned %d and halt states are %t/%t", status, firstPlan.Halted, secondPlan.Halted)
	}
	if status := request(http.MethodPost, halt, second, second); status != http.StatusOK || firstPlan.Halted || !secondPlan.Halted {
		t.Fatalf("matching confirmation returned %d and halt states are %t/%t", status, firstPlan.Halted, secondPlan.Halted)
	}
	if status := request(http.MethodGet, "/v1/rollouts", first); status != http.StatusOK {
		t.Fatalf("existing client without tenant hint returned %d", status)
	}
}
