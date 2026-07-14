// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
)

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func testFleet(n int, version string) []FleetAgent {
	fleet := make([]FleetAgent, 0, n)
	for i := 0; i < n; i++ {
		fleet = append(fleet, FleetAgent{
			ID:       agentID(i),
			TenantID: "t1",
			Version:  version,
			LastSeen: t0,
		})
	}
	return fleet
}

func agentID(i int) string { return "agent-" + string(rune('a'+i/26)) + string(rune('a'+i%26)) }

func goodArtifact() VerifiedArtifact {
	return VerifiedArtifact{
		Version:    "v0.2.0",
		Digest:     "sha256:abc123",
		Method:     "cosign verify ghcr.io/imfeelingtheagi/probectl-ebpf-agent@sha256:abc123",
		VerifiedBy: "ops@example.com",
	}
}

func mustPlan(t *testing.T, fleet []FleetAgent) *RolloutPlan {
	t.Helper()
	p, err := PlanRollout(fleet, goodArtifact(), lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// upgraded returns the fleet with the given wave's members on the target
// version with fresh heartbeats.
func upgraded(fleet []FleetAgent, w *Wave, version string, seen time.Time) []FleetAgent {
	in := map[string]bool{}
	for _, id := range w.AgentIDs {
		in[id] = true
	}
	out := append([]FleetAgent(nil), fleet...)
	for i := range out {
		if in[out[i].ID] {
			out[i].Version = version
			out[i].LastSeen = seen
		}
	}
	return out
}

func TestPlanRolloutWavesAreDeterministicAndOrdered(t *testing.T) {
	fleet := testFleet(100, "v0.1.0")
	p1 := mustPlan(t, fleet)
	p2 := mustPlan(t, fleet)

	if len(p1.Waves) == 0 || len(p1.Waves) > 3 {
		t.Fatalf("waves = %d", len(p1.Waves))
	}
	// Deterministic: identical input → identical plan.
	if p1.Progress() != p2.Progress() {
		t.Fatalf("plans differ:\n%s\n%s", p1.Progress(), p2.Progress())
	}
	// Ordered canary → early → main, jointly covering the whole fleet once.
	order := map[lifecycle.Cohort]int{lifecycle.CohortCanary: 0, lifecycle.CohortEarly: 1, lifecycle.CohortMain: 2}
	total := 0
	last := -1
	for _, w := range p1.Waves {
		if order[w.Cohort] <= last {
			t.Fatalf("wave order wrong: %s after %d", w.Cohort, last)
		}
		last = order[w.Cohort]
		total += len(w.AgentIDs)
		if w.Status != WavePending {
			t.Fatalf("fresh wave status = %s", w.Status)
		}
	}
	if total != 100 {
		t.Fatalf("waves cover %d agents, want 100", total)
	}
	// The canary ring is small — that is its job.
	if first := p1.Waves[0]; first.Cohort == lifecycle.CohortCanary && len(first.AgentIDs) >= 25 {
		t.Fatalf("canary wave too large: %d", len(first.AgentIDs))
	}
}

func TestPlanRolloutExcludesAgentsAlreadyOnTarget(t *testing.T) {
	fleet := testFleet(10, "v0.1.0")
	fleet[3].Version = "v0.2.0"
	p := mustPlan(t, fleet)
	for _, w := range p.Waves {
		for _, id := range w.AgentIDs {
			if id == fleet[3].ID {
				t.Fatal("an agent already on the target was planned for upgrade")
			}
		}
	}
	// A fully-upgraded fleet has nothing to do.
	if _, err := PlanRollout(testFleet(5, "v0.2.0"), goodArtifact(), lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy()); err == nil {
		t.Fatal("planning over an up-to-date fleet must refuse")
	}
}

func TestPlanRolloutRefusesUnattestedArtifacts(t *testing.T) {
	fleet := testFleet(5, "v0.1.0")
	for name, mutate := range map[string]func(*VerifiedArtifact){
		"no version":  func(a *VerifiedArtifact) { a.Version = "" },
		"no digest":   func(a *VerifiedArtifact) { a.Digest = "" },
		"no method":   func(a *VerifiedArtifact) { a.Method = "" },
		"no verifier": func(a *VerifiedArtifact) { a.VerifiedBy = "" },
	} {
		a := goodArtifact()
		mutate(&a)
		if _, err := PlanRollout(fleet, a, lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy()); err == nil {
			t.Fatalf("%s: unattested artifact must refuse to plan (C6)", name)
		}
	}
}

func TestPlanRolloutKeepsTheSkewGateGreen(t *testing.T) {
	fleet := testFleet(5, "v0.1.0")
	a := goodArtifact()
	a.Version = "v0.4.0" // two minors past the control plane: outside N/N-1
	if _, err := PlanRollout(fleet, a, lifecycle.DefaultSplit(), "v0.2.0", lifecycle.DefaultPolicy()); err == nil ||
		!strings.Contains(err.Error(), "skew") {
		t.Fatalf("skew-breaking target must refuse, got %v", err)
	}
}

func TestRolloutWaveHappyPath(t *testing.T) {
	fleet := testFleet(60, "v0.1.0")
	p := mustPlan(t, fleet)

	now := t0
	for !p.Done() {
		w, err := p.Advance(now)
		if err != nil {
			t.Fatal(err)
		}
		// The orchestrator applies; the registry converges within the window.
		now = now.Add(2 * time.Minute)
		fleet = upgraded(fleet, w, "v0.2.0", now)
		complete, err := p.Verify(fleet, now)
		if err != nil || !complete {
			t.Fatalf("wave %s: complete=%v err=%v", w.Cohort, complete, err)
		}
	}
	if p.CurrentWave() != nil || p.Halted {
		t.Fatalf("done rollout: %s", p.Progress())
	}
}

func TestRolloutWavesNeverOverlapOrSkip(t *testing.T) {
	p := mustPlan(t, testFleet(60, "v0.1.0"))
	if _, err := p.Advance(t0); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Advance(t0); err == nil {
		t.Fatal("advancing past an unverified wave must refuse")
	}
	if _, err := p.Verify(nil, t0.Add(time.Minute)); err == nil {
		// nil registry snapshot: every member missing — but inside the window
		// it just keeps converging; no error, no halt.
		if p.Halted {
			t.Fatal("halted inside the verify window")
		}
	}
}

func TestRolloutHaltsOnStragglerAfterWindow(t *testing.T) {
	fleet := testFleet(60, "v0.1.0")
	p := mustPlan(t, fleet)
	w, err := p.Advance(t0)
	if err != nil {
		t.Fatal(err)
	}

	// All but one member upgrade; the straggler stays on the old version.
	now := t0.Add(time.Minute)
	fleet = upgraded(fleet, w, "v0.2.0", now)
	for i := range fleet {
		if fleet[i].ID == w.AgentIDs[0] {
			fleet[i].Version = "v0.1.0"
		}
	}

	// Inside the window: patient, not halted.
	if complete, err := p.Verify(fleet, now); complete || err != nil || p.Halted {
		t.Fatalf("inside window: complete=%v err=%v halted=%v", complete, err, p.Halted)
	}
	// Past the window: HALT, loudly, naming the straggler.
	late := t0.Add(p.VerifyWindow + time.Minute)
	if _, err := p.Verify(fleet, late); err == nil || !p.Halted {
		t.Fatalf("straggler past the window must halt, err=%v halted=%v", err, p.Halted)
	}
	if !strings.Contains(p.HaltReason, w.AgentIDs[0]) || !strings.Contains(p.HaltReason, "still on v0.1.0") {
		t.Fatalf("halt reason must name the straggler: %s", p.HaltReason)
	}
	// Halted = frozen: no advance, no verify.
	if _, err := p.Advance(late); err == nil {
		t.Fatal("advance while halted must refuse")
	}
	if p.CurrentWave() != nil {
		t.Fatal("halted rollout must expose no current wave")
	}
}

func TestRolloutHaltsWhenAnUpgradedAgentGoesDark(t *testing.T) {
	fleet := testFleet(40, "v0.1.0")
	p := mustPlan(t, fleet)
	w, err := p.Advance(t0)
	if err != nil {
		t.Fatal(err)
	}
	// Everyone reports the target… but one agent's heartbeat died at upgrade.
	fleet = upgraded(fleet, w, "v0.2.0", t0.Add(time.Minute))
	dark := w.AgentIDs[len(w.AgentIDs)-1]
	for i := range fleet {
		if fleet[i].ID == dark {
			fleet[i].LastSeen = t0 // never seen again
		}
	}
	late := t0.Add(p.VerifyWindow + time.Minute)
	if _, err := p.Verify(fleet, late); err == nil || !p.Halted {
		t.Fatal("dark agent past the window must halt")
	}
	if !strings.Contains(p.HaltReason, dark) || !strings.Contains(p.HaltReason, "dark") {
		t.Fatalf("halt reason must flag the dark agent: %s", p.HaltReason)
	}
}

func TestRolloutResumeIsExplicitAndRecovers(t *testing.T) {
	fleet := testFleet(40, "v0.1.0")
	p := mustPlan(t, fleet)
	w, _ := p.Advance(t0)
	late := t0.Add(p.VerifyWindow + time.Minute)
	_, _ = p.Verify(fleet, late) // nothing upgraded → halt

	if err := p.Resume("  ", late); err == nil {
		t.Fatal("resume without a remediation note must refuse")
	}
	if err := p.Resume("straggler node replaced", late); err != nil {
		t.Fatal(err)
	}
	// The failed wave re-applies with a fresh window and can now complete.
	now := late.Add(time.Minute)
	fleet = upgraded(fleet, w, "v0.2.0", now)
	if complete, err := p.Verify(fleet, now); !complete || err != nil {
		t.Fatalf("post-resume verify: complete=%v err=%v", complete, err)
	}
	if err := p.Resume("nothing is halted", now); err == nil {
		t.Fatal("resume on a healthy rollout must refuse")
	}
}
