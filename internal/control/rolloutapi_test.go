// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
)

// OPS-002: the manager plans a rollout, steps it via the engine, and halt/
// resume gate advancement (the operator surface over the rollout state machine).
func TestRolloutManagerLifecycle(t *testing.T) {
	m := newRolloutManager()
	fleet := []agent.FleetAgent{
		{ID: "a1", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
		{ID: "a2", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
		{ID: "a3", TenantID: "t", Version: "v0.1.0", LastSeen: time.Now()},
	}
	art := agent.VerifiedArtifact{Version: "v0.2.0", Digest: "sha256:abc", Method: "cosign ...", VerifiedBy: "op"}
	plan, err := agent.PlanRollout(fleet, art, lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy())
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
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rollout create JSON contract drifted:\ngot  %v\nwant %v", got, want)
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
