// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
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
