// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

// DPR-192: observed on the lab. A flow collector sat 1/1 Running for ninety
// minutes, logging contented all-zero collector stats every sixty seconds, while
// the fleet view called it offline and told the operator to "inspect its last
// authenticated heartbeat" and "review transport and agent logs". Both are
// impossible for that agent: a collector registered with `register-collector`
// publishes to the bus and is given no cert and no gRPC lane (ARCH-011), so
// there is no heartbeat to inspect, and its logs said everything was fine —
// which was true. What had actually happened was that no exporter had sent it a
// packet since the flow senders finished.
//
// The state is right and stays right. The sentences have to be about the thing
// an operator can actually go and look at.
func TestFleetTellsABusCollectorTheTruthAboutItsSilence(t *testing.T) {
	now := time.Date(2026, 9, 18, 21, 0, 0, 0, time.UTC)
	seen := now.Add(-90 * time.Minute) // the lab's actual gap
	identities := map[string]store.AgentIdentityWindow{}

	collector := store.Agent{
		ID: "agent-flow", TenantID: "tenant-a", Name: "helm-flow-1",
		AgentVersion: "v1.4.2", Status: "offline", LastSeenAt: &seen,
		Capabilities: []string{"collector", "flow"},
	}
	lane := collector
	lane.ID, lane.Name = "agent-host", "laptop-linux-1"
	lane.Capabilities = []string{"http", "icmp"}

	views, err := buildFleetAgentViews([]store.Agent{collector, lane}, nil, identities, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	gotCollector, gotLane := views[0], views[1]

	// Both are stale, because both are. That is not what changed.
	if gotCollector.HeartbeatState != "stale" || gotLane.HeartbeatState != "stale" {
		t.Fatalf("both should read stale, got %q and %q", gotCollector.HeartbeatState, gotLane.HeartbeatState)
	}
	if gotCollector.HeartbeatAgeSeconds == nil || *gotCollector.HeartbeatAgeSeconds != 5400 {
		t.Fatalf("the age must still be reported: %v", gotCollector.HeartbeatAgeSeconds)
	}

	// The collector is not told to inspect something it does not have.
	if strings.Contains(gotCollector.HeartbeatReason, "heartbeat lane of its own") == false {
		t.Errorf("a collector's reason must say it has no heartbeat lane: %q", gotCollector.HeartbeatReason)
	}
	if strings.Contains(gotCollector.HeartbeatReason, "inspect its last authenticated heartbeat") {
		t.Errorf("a collector has no authenticated heartbeat to inspect: %q", gotCollector.HeartbeatReason)
	}
	if !strings.Contains(gotCollector.HeartbeatReason, "telemetry") {
		t.Errorf("a collector's liveness IS its telemetry; the reason must say so: %q", gotCollector.HeartbeatReason)
	}
	if gotCollector.NextSafeAction.Kind != "inspect_collector_input" {
		t.Errorf("next safe action = %q, want inspect_collector_input", gotCollector.NextSafeAction.Kind)
	}
	// The one sentence that would have saved ninety minutes on the lab.
	if !strings.Contains(gotCollector.NextSafeAction.Reason, "logs will look healthy") {
		t.Errorf("the action must warn that the agent's own logs look fine: %q", gotCollector.NextSafeAction.Reason)
	}

	// And an agent that DOES hold a gRPC lane keeps the advice that fits it.
	if gotLane.NextSafeAction.Kind != "inspect_heartbeat" {
		t.Errorf("a lane agent must still be sent to its heartbeat: %q", gotLane.NextSafeAction.Kind)
	}
	if !strings.Contains(gotLane.HeartbeatReason, "inspect its last authenticated heartbeat") {
		t.Errorf("a lane agent's reason must not have been rewritten: %q", gotLane.HeartbeatReason)
	}
}

// A collector that is publishing normally must read as ready, and say why in its
// own terms — otherwise the fix would only have moved the confusion.
func TestFleetDescribesAHealthyCollectorInItsOwnTerms(t *testing.T) {
	now := time.Date(2026, 9, 18, 21, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second)
	row := store.Agent{
		ID: "agent-flow", TenantID: "tenant-a", Name: "helm-flow-1",
		AgentVersion: "v1.4.2", Status: "online", LastSeenAt: &fresh,
		Capabilities: []string{"collector", "flow"},
	}
	views, err := buildFleetAgentViews([]store.Agent{row}, nil, map[string]store.AgentIdentityWindow{}, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	got := views[0]
	if got.HeartbeatState != "ready" || got.ReadinessState != "ready" {
		t.Fatalf("a publishing collector must read ready, got %s/%s", got.HeartbeatState, got.ReadinessState)
	}
	if !strings.Contains(got.HeartbeatReason, "Telemetry") {
		t.Errorf("a healthy collector's reason must be about its telemetry: %q", got.HeartbeatReason)
	}

	// Never registered at all: it has published nothing, which is the honest
	// statement — not that it failed to complete a handshake it never attempts.
	row.LastSeenAt, row.Status = nil, "registered"
	views, err = buildFleetAgentViews([]store.Agent{row}, nil, map[string]store.AgentIdentityWindow{}, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(views[0].HeartbeatReason, "published no telemetry") {
		t.Errorf("a never-seen collector must be described by what it has not published: %q", views[0].HeartbeatReason)
	}
	if views[0].NextSafeAction.Kind != "inspect_collector_input" {
		t.Errorf("next safe action = %q, want inspect_collector_input", views[0].NextSafeAction.Kind)
	}
}
