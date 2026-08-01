// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestOnboardingProgressTenantResultIsolation(t *testing.T) {
	results := NewLatestResults(10)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	results.Record("tenant-a", ResultView{
		AgentID: "agent-a", Type: "http", Target: "checkout.tenant-a.example",
		Success: false, ObservedAt: now,
	})

	var tenantA, tenantB onboardingProgressResponse
	applyOnboardingResults(&tenantA, results.List("tenant-a"))
	applyOnboardingResults(&tenantB, results.List("tenant-b"))

	if !tenantA.FirstResultReceived || !tenantA.FirstFindingVisible || tenantA.FirstFinding == nil {
		t.Fatalf("tenant A did not receive its finding: %+v", tenantA)
	}
	if tenantA.FirstFinding.Target != "checkout.tenant-a.example" {
		t.Fatalf("tenant A finding target = %q", tenantA.FirstFinding.Target)
	}
	if tenantB.FirstResultReceived || tenantB.FirstFindingVisible || tenantB.FirstFinding != nil {
		t.Fatalf("tenant B received tenant A progress: %+v", tenantB)
	}
}

func TestOnboardingProgressMilestonesExcludeToken(t *testing.T) {
	out := onboardingProgressResponse{AgentEnrollTokenCreated: true, FirstTestCreated: true, ScimTokenCreated: true}
	setOnboardingReadinessCount(&out)
	if out.ReadinessStepsComplete != 0 || out.ReadinessStepsTotal != 4 {
		t.Fatalf("setup artifacts advanced readiness: %+v", out)
	}

	out.AgentConnected = true
	out.ProducerHealthy = true
	out.FirstResultReceived = true
	out.FirstFindingVisible = true
	out.ReadinessStepsComplete = 0
	setOnboardingReadinessCount(&out)
	if out.ReadinessStepsComplete != 4 {
		t.Fatalf("operational milestones = %d, want 4", out.ReadinessStepsComplete)
	}
}

func TestOnboardingProgressProducerStates(t *testing.T) {
	rows := []store.ProducerReadiness{
		{ID: "synthetic", Registered: true, Connected: true, Healthy: true},
		{ID: "flow", Registered: true, Connected: true},
		{ID: "bgp", Registered: true},
		{ID: "endpoint"},
	}
	got := onboardingProducerReadiness(rows, func(string) bool { return true })
	want := []onboardingReadinessState{onboardingReady, onboardingBlocked, onboardingBlocked, onboardingBlocked}
	for i := range want {
		if got[i].State != want[i] || got[i].NextAction == "" {
			t.Fatalf("producer %s = %+v, want state %s and a next action", rows[i].ID, got[i], want[i])
		}
	}
}

func TestOnboardingProgressProducerNextActionsAreAuthorized(t *testing.T) {
	rows := []store.ProducerReadiness{{ID: "synthetic", Registered: true, Connected: true, Healthy: true}}
	got := onboardingProducerReadiness(rows, func(string) bool { return false })
	if len(got) != 1 || got[0].NextAction != "/onboarding" {
		t.Fatalf("unauthorized producer action escaped: %+v", got)
	}
}

func TestOnboardingProgressEngineInventory(t *testing.T) {
	server := &Server{cfg: &config.Config{NDREnabled: true, SIEMEnabled: true, CTEnabled: true}}
	items, err := server.onboardingEngineReadiness(
		context.Background(), tenancy.Scope{Tenant: "tenant-a"}, nil,
		func(string) bool { return true },
	)
	if err != nil {
		t.Fatalf("engine readiness: %v", err)
	}
	got := make(map[string]onboardingReadiness, len(items))
	for _, item := range items {
		got[item.ID] = item
		if item.State != onboardingReady && item.State != onboardingQuiet && item.State != onboardingBlocked {
			t.Fatalf("engine %s has invalid state %q", item.ID, item.State)
		}
		if item.NextAction == "" {
			t.Fatalf("engine %s has no authorized next action", item.ID)
		}
	}
	for _, id := range []string{
		"synthetic-results", "flow-analytics", "otlp", "device-telemetry", "ebpf",
		"topology", "cost", "slo", "alerting", "compliance", "outage", "rum",
		"carbon", "tls-posture", "ct-correlation", "threat-intel", "ndr",
		"threat-detections", "endpoint-dem", "secrets", "cmdb", "outage-feeds",
		"oncall-dispatch", "siem-export",
	} {
		if _, ok := got[id]; !ok {
			t.Errorf("config-gated engine %s is missing", id)
		}
	}
}

func TestOnboardingProgressPermissionGateFailsClosed(t *testing.T) {
	server := &Server{cfg: &config.Config{NDREnabled: true, SIEMEnabled: true, CTEnabled: true}}
	items, err := server.onboardingEngineReadiness(
		context.Background(), tenancy.Scope{Tenant: "tenant-a"}, nil,
		func(string) bool { return false },
	)
	if err != nil {
		t.Fatalf("engine readiness: %v", err)
	}
	for _, item := range items {
		if item.State != onboardingBlocked || item.NextAction != "/onboarding" {
			t.Fatalf("unauthorized engine %s leaked readiness/action: %+v", item.ID, item)
		}
	}
}
