// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/device"
)

const deviceConfigChangeSource = "probectl-device-config"

// projectedConfigChanges derives one safe change event for every actual device
// config drift with an exact predecessor. ConfigVersion remains the canonical
// record: this projection creates no second write, retention policy, or copy of
// config content.
func projectedConfigChanges(ctx context.Context, ops device.OpsStore, tenant string) ([]change.Event, error) {
	if ops == nil {
		return nil, nil
	}
	configs, err := ops.ListConfigs(ctx, tenant, device.OpsFilter{Limit: deviceMaxLimit})
	if err != nil {
		return nil, err
	}
	return projectConfigChanges(configs, tenant), nil
}

func projectConfigChanges(configs []device.ConfigVersion, tenant string) []change.Event {
	if tenant == "" {
		return nil
	}
	byDeviceVersion := make(map[string]device.ConfigVersion, len(configs))
	for _, cfg := range configs {
		if cfg.TenantID != tenant || cfg.Device == "" || cfg.Version <= 0 {
			continue
		}
		byDeviceVersion[configVersionKey(cfg, cfg.Version)] = cfg
	}

	events := make([]change.Event, 0, len(configs))
	for _, current := range configs {
		if current.TenantID != tenant || !current.Drifted || current.Version <= 1 ||
			current.ID == "" || current.Content == "" || current.ContentHash == "" ||
			current.PreviousHash == "" || current.Device == "" {
			continue
		}
		previous, ok := byDeviceVersion[configVersionKey(current, current.Version-1)]
		if !ok || previous.TenantID != tenant || previous.ID == "" || previous.Content == "" ||
			previous.ContentHash == "" || previous.ContentHash != current.PreviousHash {
			continue
		}
		occurredAt := current.ObservedAt.UTC()
		if occurredAt.IsZero() {
			occurredAt = current.ArchivedAt.UTC()
		}
		if occurredAt.IsZero() {
			continue
		}
		var binding *change.ConfigBindingReference
		if current.Binding != nil {
			value := change.ConfigBindingReference(*current.Binding)
			binding = &value
		}
		events = append(events, change.Event{
			ID:       "device-config:" + current.ID,
			TenantID: tenant,
			Source:   deviceConfigChangeSource,
			Kind:     change.KindConfig,
			Title:    fmt.Sprintf("Config drift detected on %s", current.Device),
			Summary: fmt.Sprintf(
				"Redacted device config changed from version %d to %d.",
				previous.Version,
				current.Version,
			),
			Target: current.Device,
			Ref:    current.ID,
			Config: &change.ConfigReference{
				CurrentID:       current.ID,
				CurrentVersion:  current.Version,
				CurrentHash:     current.ContentHash,
				PreviousID:      previous.ID,
				PreviousVersion: previous.Version,
				PreviousHash:    previous.ContentHash,
				Binding:         binding,
			},
			OccurredAt: occurredAt,
			ReceivedAt: current.ArchivedAt.UTC(),
		})
	}
	sortChangeEvents(events)
	return events
}

func configVersionKey(cfg device.ConfigVersion, version int) string {
	if cfg.Binding == nil {
		return fmt.Sprintf("%s\x00%s\x00%d", cfg.TenantID, cfg.Device, version)
	}
	b := cfg.Binding
	encoded, _ := json.Marshal([]any{cfg.TenantID, b.Kind, b.ContextID, b.DeviceEntityID, b.AgentID, b.SourceRef, b.SourceAssignedAt.UTC().Format(time.RFC3339Nano), b.AgentAssignedAt.UTC().Format(time.RFC3339Nano), version})
	return string(encoded)
}

func mergeChangeEvents(limit int, groups ...[]change.Event) []change.Event {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	merged := make([]change.Event, 0)
	for _, group := range groups {
		for _, event := range group {
			if event.ID != "" {
				if _, ok := seen[event.ID]; ok {
					continue
				}
				seen[event.ID] = struct{}{}
			}
			merged = append(merged, event)
		}
	}
	sortChangeEvents(merged)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

func sortChangeEvents(events []change.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		left, right := events[i].OccurredAt, events[j].OccurredAt
		if left.Equal(right) {
			return events[i].ID < events[j].ID
		}
		return left.After(right)
	})
}

func changesBetween(events []change.Event, start, end time.Time) []change.Event {
	out := make([]change.Event, 0, len(events))
	for _, event := range events {
		if event.OccurredAt.Before(start) || event.OccurredAt.After(end) {
			continue
		}
		out = append(out, event)
	}
	return out
}
