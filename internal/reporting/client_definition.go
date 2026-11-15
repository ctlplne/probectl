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

// ClientReportDefinition selects a calendar month or explicit assessment
// interval with capacity assumptions. Empty month selects the prior month.
type ClientReportDefinition struct {
	Timezone        string                       `json:"timezone,omitempty"`
	Period          string                       `json:"period,omitempty"`
	Month           string                       `json:"month,omitempty"`
	Assessment      *ClientReportAssessment      `json:"assessment,omitempty"`
	CapacityTargets []ClientReportCapacityTarget `json:"capacity_targets"`
}

// Assessment selects exact past bounds; it grants neither collection nor
// offboarding authority. Preparer is an operator-supplied report attribution.
type ClientReportAssessment struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Preparer string `json:"preparer"`
}
