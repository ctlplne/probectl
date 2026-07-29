// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/device"
)

func TestProjectConfigChangesRequiresExactTenantPredecessor(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	config := func(id, tenant, target, content, hash, previousHash string, version int, drifted bool, offset time.Duration) device.ConfigVersion {
		return device.ConfigVersion{
			ID: id, TenantID: tenant, Device: target, Version: version, Content: content,
			ContentHash: hash, PreviousHash: previousHash, Drifted: drifted,
			ObservedAt: now.Add(offset), ArchivedAt: now.Add(offset + time.Minute),
		}
	}
	rows := []device.ConfigVersion{
		config("current", "tenant-a", "edge-r1", "hostname edge-r1\nsecret [REDACTED]", "hash-2", "hash-1", 2, true, 0),
		config("previous", "tenant-a", "edge-r1", "hostname edge-r1", "hash-1", "", 1, false, -time.Hour),
		config("unchanged", "tenant-a", "edge-r2", "same", "same-hash", "same-hash", 2, false, 0),
		config("missing-content", "tenant-a", "edge-r3", "", "hash-3", "hash-2", 2, true, 0),
		config("wrong-tenant", "tenant-b", "edge-r1", "foreign", "hash-b", "hash-a", 2, true, 0),
	}

	got := projectConfigChanges(rows, "tenant-a")
	if len(got) != 1 {
		t.Fatalf("projected events = %d, want 1: %#v", len(got), got)
	}
	event := got[0]
	if event.ID != "device-config:current" || event.Target != "edge-r1" ||
		event.Kind != change.KindConfig || event.Ref != "current" {
		t.Fatalf("unexpected projected event: %#v", event)
	}
	if event.Config == nil || event.Config.CurrentID != "current" ||
		event.Config.PreviousID != "previous" || event.Config.PreviousHash != "hash-1" {
		t.Fatalf("unexpected config reference: %#v", event.Config)
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hostname") || strings.Contains(string(body), "secret") {
		t.Fatalf("projected event leaked config content: %s", body)
	}
}

func TestMergeChangeEventsOrdersBoundsAndDeduplicates(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	left := []change.Event{
		{ID: "older", OccurredAt: now.Add(-time.Hour)},
		{ID: "duplicate", OccurredAt: now.Add(-2 * time.Hour)},
	}
	right := []change.Event{
		{ID: "newer", OccurredAt: now},
		{ID: "duplicate", OccurredAt: now.Add(time.Hour)},
	}

	got := mergeChangeEvents(2, left, right)
	if len(got) != 2 || got[0].ID != "newer" || got[1].ID != "older" {
		t.Fatalf("merge = %#v, want newer then older with duplicate removed", got)
	}
}

func TestChangeEventsSourceProjectsConfigDriftWithoutDatabase(t *testing.T) {
	ops := device.NewMemoryOpsStore()
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	for i, content := range []string{"hostname edge-r1\nshutdown", "hostname edge-r1\nno shutdown"} {
		if _, err := ops.ArchiveConfig(context.Background(), device.ConfigVersion{
			TenantID: "tenant-a", Device: "edge-r1", Source: "fixture",
			Content: content, ObservedAt: now.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := (changeEventsSource{configs: ops}).QueryEvents(
		context.Background(),
		"tenant-a",
		map[string]string{"type": "change", "target": "edge-r1"},
		ai.TimeRange{Start: now.Add(-time.Minute), End: now.Add(2 * time.Minute)},
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("AI rows = %d, want 1: %#v", len(rows), rows)
	}
	if rows[0]["id"] != "device-config:config-2" ||
		rows[0]["config_current_id"] != "config-2" ||
		rows[0]["config_previous_id"] != "config-1" ||
		rows[0]["config_current_hash"] == "" ||
		rows[0]["config_previous_hash"] == "" {
		t.Fatalf("AI row did not preserve the canonical config reference: %#v", rows[0])
	}
	if _, ok := rows[0]["content"]; ok {
		t.Fatalf("AI row must not include config content: %#v", rows[0])
	}

	foreign, err := (changeEventsSource{configs: ops}).QueryEvents(
		context.Background(),
		"tenant-b",
		map[string]string{"type": "change"},
		ai.TimeRange{Start: now.Add(-time.Minute), End: now.Add(2 * time.Minute)},
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 0 {
		t.Fatalf("foreign tenant received config evidence: %#v", foreign)
	}
}
