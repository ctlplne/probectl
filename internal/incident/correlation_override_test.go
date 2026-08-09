// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package incident

import (
	"context"
	"testing"
	"time"
)

func TestCorrelationExplanationAndDurableOverrideDecision(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	correlator := NewCorrelator(store, 5*time.Minute, nil)
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	root, err := correlator.Ingest(ctx, Signal{
		TenantID: "tenant-a", Plane: "network", Kind: "alert.firing",
		Title: "loss", Target: "192.0.2.10", Severity: SeverityWarning, OccurredAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	grouped, err := correlator.Ingest(ctx, Signal{
		TenantID: "tenant-a", Plane: "bgp", Kind: "bgp.origin_change",
		Title: "route change", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24",
		Severity: SeverityWarning, OccurredAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if grouped.ID != root.ID {
		t.Fatalf("automatic correlation opened %s, want parent %s", grouped.ID, root.ID)
	}
	stored := store.get(root.ID)
	metadata := stored.Signals[1].Attributes
	if metadata["correlation.parent_incident_id"] != root.ID || metadata["correlation.reason"] != "within_window_and_shared_target_or_prefix" || metadata["correlation.match_confidence"] != "1.00" || metadata["correlation.freshness_seconds"] == "" {
		t.Fatalf("grouping explanation incomplete: %v", metadata)
	}

	override := CorrelationOverride{
		ID: "override-1", TenantID: "tenant-a", SourceIncidentID: root.ID,
		DetachedIncidentID: "detached-placeholder", Plane: "bgp", Kind: "bgp.origin_change",
		Target: "192.0.2.0/24", Prefix: "192.0.2.0/24", Active: true,
	}
	store.putCorrelationOverride(override)
	detached, err := correlator.Ingest(ctx, Signal{
		TenantID: "tenant-a", Plane: "bgp", Kind: "bgp.origin_change",
		Title: "independently important route change", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24",
		Severity: SeverityCritical, OccurredAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if detached.ID == root.ID {
		t.Fatal("active override silently regrouped into excluded parent")
	}
	detachedStored := store.get(detached.ID)
	detachedMetadata := detachedStored.Signals[0].Attributes
	if detachedMetadata["correlation.override_id"] != override.ID || detachedMetadata["correlation.excluded_parent_incident_id"] != root.ID {
		t.Fatalf("override explanation incomplete: %v", detachedMetadata)
	}

	// Explicit reversal removes the exclusion for later runs; it never deletes
	// either existing incident or either timeline.
	override.Active = false
	store.putCorrelationOverride(override)
	if _, err := correlator.Ingest(ctx, Signal{
		TenantID: "tenant-a", Plane: "bgp", Kind: "bgp.origin_change",
		Title: "after reversal", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24",
		Severity: SeverityWarning, OccurredAt: now.Add(3 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 2 {
		t.Fatalf("reversal erased or invented incident evidence: got %d incidents", store.Len())
	}
}

func TestCorrelationOverrideNeverMatchesAcrossTenants(t *testing.T) {
	store := NewMemoryStore()
	store.putCorrelationOverride(CorrelationOverride{
		ID: "override-a", TenantID: "tenant-a", SourceIncidentID: "inc-a",
		Plane: "network", Kind: "alert.firing", Target: "192.0.2.10", Active: true,
	})
	overrides, err := store.ActiveCorrelationOverrides(context.Background(), "tenant-b", Signal{
		TenantID: "tenant-b", Plane: "network", Kind: "alert.firing", Target: "192.0.2.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 0 {
		t.Fatalf("cross-tenant override matched: %+v", overrides)
	}
}
