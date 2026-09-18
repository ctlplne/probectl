// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/lifecycle"
	"github.com/ctlplne/probectl/internal/store"
)

func TestFleetHealthTenantJoinUsesOnlyScopedRows(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	stale := now.Add(-10 * time.Minute)
	rows := []store.Agent{
		{ID: "tenant-a-ready", TenantID: "tenant-a", Name: "ready", AgentVersion: "v1.4.2", Status: "online", Capabilities: []string{"flow"}, LastSeenAt: &recent},
		{ID: "tenant-a-stale", TenantID: "tenant-a", Name: "stale", AgentVersion: "v1.3.9", Status: "online", Capabilities: []string{"ebpf"}, LastSeenAt: &stale},
		{ID: "tenant-a-never", TenantID: "tenant-a", Name: "never", AgentVersion: "v1.1.0", Status: "registered", Capabilities: nil},
	}
	plan := &agent.RolloutPlan{
		Target: agent.VerifiedArtifact{Version: "v1.4.2", Digest: "sha256:abababababababababababababababababababababababababababababababab", Method: "cosign verify", VerifiedBy: "operator"},
		Waves:  []agent.Wave{{Cohort: lifecycle.CohortCanary, AgentIDs: []string{"tenant-a-stale"}, Status: agent.WaveApplying}},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	views, err := buildFleetAgentViews(rows, []store.RolloutRecord{{ID: "rollout-a", TenantID: "tenant-a", Plan: raw}}, nil, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 3 {
		t.Fatalf("views = %d, want 3", len(views))
	}
	if views[0].ReadinessState != "ready" || views[0].HeartbeatAgeSeconds == nil || *views[0].HeartbeatAgeSeconds != 60 {
		t.Fatalf("ready view = %+v", views[0])
	}
	if views[1].ReadinessState != "stale" || views[1].RolloutID != "rollout-a" || views[1].RolloutCohort != "canary" || views[1].RolloutState != "applying" {
		t.Fatalf("stale rollout view = %+v", views[1])
	}
	if views[1].NextSafeAction.Kind != "verify_rollout_wave" {
		t.Fatalf("applying next action = %+v", views[1].NextSafeAction)
	}
	if views[2].ReadinessState != "never_connected" || views[2].VersionState != "unsupported" {
		t.Fatalf("never-seen view = %+v", views[2])
	}

	encoded, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "tenant-b") {
		t.Fatalf("fleet view leaked a tenant not present in RLS-scoped inputs: %s", encoded)
	}
}

func TestFleetHealthRolloutHaltRequiresHumanReview(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Minute)
	row := store.Agent{ID: "a1", TenantID: "tenant-a", AgentVersion: "v1.4.2", Status: "online", Capabilities: []string{"flow"}, LastSeenAt: &seen}
	plan := &agent.RolloutPlan{
		Target:     agent.VerifiedArtifact{Version: "v1.5.0"},
		Waves:      []agent.Wave{{Cohort: lifecycle.CohortCanary, AgentIDs: []string{"a1"}, Status: agent.WaveHalted}},
		Halted:     true,
		HaltReason: "canary heartbeat failed",
	}
	raw, _ := json.Marshal(plan)
	views, err := buildFleetAgentViews([]store.Agent{row}, []store.RolloutRecord{{ID: "r1", Plan: raw}}, nil, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	got := views[0]
	if !got.RolloutHalted || got.RolloutState != "halted" || got.LastFailure != plan.HaltReason {
		t.Fatalf("halted view = %+v", got)
	}
	if got.NextSafeAction.Kind != "review_halted_rollout" || strings.Contains(strings.ToLower(got.NextSafeAction.Label), "execute") {
		t.Fatalf("halted action must remain human review only: %+v", got.NextSafeAction)
	}
}

func TestFleetHealthStatesAreHonestAndDistinct(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	rows := []store.Agent{
		{ID: "cap-gap", AgentVersion: "v1.4.0", Status: "online", LastSeenAt: &recent},
		{ID: "skew", AgentVersion: "v1.2.0", Status: "online", Capabilities: []string{"flow"}, LastSeenAt: &recent},
		{ID: "supported-skew", AgentVersion: "v1.3.0", Status: "online", Capabilities: []string{"flow"}, LastSeenAt: &recent},
	}
	views, err := buildFleetAgentViews(rows, nil, nil, "v1.4.0", now)
	if err != nil {
		t.Fatal(err)
	}
	if views[0].ReadinessState != "unsupported_capability" {
		t.Fatalf("capability gap = %q", views[0].ReadinessState)
	}
	if views[1].ReadinessState != "version_skew" || views[1].VersionState != "unsupported" {
		t.Fatalf("unsupported skew = %+v", views[1])
	}
	if views[2].ReadinessState != "version_skew" || views[2].VersionState != "supported_skew" {
		t.Fatalf("supported skew = %+v", views[2])
	}
}
