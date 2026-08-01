// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
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
		byDeviceVersion[configVersionKey(cfg.Device, cfg.Version)] = cfg
	}

	events := make([]change.Event, 0, len(configs))
	for _, current := range configs {
		if current.TenantID != tenant || !current.Drifted || current.Version <= 1 ||
			current.ID == "" || current.Content == "" || current.ContentHash == "" ||
			current.PreviousHash == "" || current.Device == "" {
			continue
		}
		previous, ok := byDeviceVersion[configVersionKey(current.Device, current.Version-1)]
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
			},
			OccurredAt: occurredAt,
			ReceivedAt: current.ArchivedAt.UTC(),
		})
	}
	sortChangeEvents(events)
	return events
}

func configVersionKey(deviceName string, version int) string {
	return fmt.Sprintf("%s\x00%d", deviceName, version)
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
