// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

// Capacity assumptions are operator configuration, never inferred inventory
// speeds, financial commitments or source grants. Generation resolves all
// canonical targets under current tenant/source permissions.
type ClientReportCapacityTarget struct {
	Target         ClientReportCapacityRef     `json:"target"`
	Direction      string                      `json:"direction"`
	CapacityBPS    string                      `json:"capacity_bps"`
	MaximumPollGap string                      `json:"maximum_poll_gap"`
	PhysicalBounds []ClientReportPhysicalBound `json:"physical_bounds"`
	ForecastMonths int                         `json:"forecast_months,omitempty"`
}

type ClientReportCapacityRef struct {
	Kind        string `json:"kind"`
	ContextID   string `json:"context_id,omitempty"`
	InterfaceID string `json:"interface_id,omitempty"`
	TagID       string `json:"tag_id,omitempty"`
	TagValue    string `json:"tag_value,omitempty"`
}

type ClientReportPhysicalBound struct {
	ContextID   string `json:"context_id"`
	InterfaceID string `json:"interface_id"`
	MaxBPS      string `json:"max_bps"`
}

// ClientReportDefinition selects an immutable month and explicit capacity
// assumptions. An empty month resolves the previous complete calendar month.
type ClientReportDefinition struct {
	Month           string                       `json:"month,omitempty"`
	CapacityTargets []ClientReportCapacityTarget `json:"capacity_targets"`
}
