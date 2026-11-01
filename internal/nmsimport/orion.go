// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"io"
)

// Orion SWIS queries return a results array. The importer requests only the
// documented columns it needs and never selects community or credential
// fields. Arbitrary source predicates and alert delivery remain inert.

// parseOrionNodes decodes a bounded SELECT of Orion.Nodes. Location is a
// source label, never a routing-context selector, and polling still needs an
// explicit target policy and tenant-owned secret reference.
func parseOrionNodes(r io.Reader) (Snapshot, error) {
	var page struct {
		Results []struct {
			ID           sourceID `json:"NodeID"`
			Caption      string   `json:"Caption"`
			IPAddress    string   `json:"IPAddress"`
			Location     string   `json:"Location"`
			PollInterval int64    `json:"PollInterval"`
		} `json:"results"`
	}
	if err := decodePage(r, &page); err != nil || page.Results == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: Orion, Rows: make([]Row, 0, len(page.Results))}
	seen := make(map[string]struct{}, len(page.Results))
	for _, node := range page.Results {
		id := string(node.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: "device", ExternalID: id, Label: safeLabel(node.Caption),
			Address: safeAddress(node.IPAddress), LocationLabel: safeLabel(node.Location),
			UnmappedCodes: []string{"site_unmapped"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		if row.Address == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_ip_address")
		}
		if node.PollInterval > 0 && node.PollInterval <= 86400 {
			row.PollSeconds = node.PollInterval
			row.UnmappedCodes = append(row.UnmappedCodes, "poll_settings_unmapped")
		} else {
			row.UnmappedCodes = append(row.UnmappedCodes, "poll_interval_unmapped")
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// parseOrionGroups decodes Orion.Container rows. Membership is queried
// separately; a group name does not select a site or VRF.
func parseOrionGroups(r io.Reader) (Snapshot, error) {
	var page struct {
		Results []struct {
			ID   sourceID `json:"ContainerID"`
			Name string   `json:"Name"`
		} `json:"results"`
	}
	if err := decodePage(r, &page); err != nil || page.Results == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: Orion, Rows: make([]Row, 0, len(page.Results))}
	seen := make(map[string]struct{}, len(page.Results))
	for _, group := range page.Results {
		id := string(group.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: "group", ExternalID: id, Label: safeLabel(group.Name),
			UnmappedCodes: []string{"membership_not_captured"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// parseOrionRules decodes Orion.AlertConfigurations identity and labels. The
// source Trigger, Reset and NotificationSettings never enter the snapshot.
func parseOrionRules(r io.Reader) (Snapshot, error) {
	var page struct {
		Results []struct {
			ID            sourceID `json:"AlertID"`
			Name          string   `json:"Name"`
			NotifyEnabled bool     `json:"NotifyEnabled"`
		} `json:"results"`
	}
	if err := decodePage(r, &page); err != nil || page.Results == nil {
		return Snapshot{}, ErrInvalidPage
	}
	out := Snapshot{Source: Orion, Rows: make([]Row, 0, len(page.Results))}
	seen := make(map[string]struct{}, len(page.Results))
	for _, rule := range page.Results {
		id := string(rule.ID)
		if id == "" || id == "0" {
			return Snapshot{}, ErrInvalidPage
		}
		if _, duplicate := seen[id]; duplicate {
			return Snapshot{}, ErrInvalidPage
		}
		seen[id] = struct{}{}
		row := Row{Kind: "rule", ExternalID: id, Label: safeLabel(rule.Name),
			UnmappedCodes: []string{"expression_unmapped"}}
		if row.Label == "" {
			row.UnmappedCodes = append(row.UnmappedCodes, "missing_safe_label")
		}
		if rule.NotifyEnabled {
			row.UnmappedCodes = append(row.UnmappedCodes, "delivery_unmapped")
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}
