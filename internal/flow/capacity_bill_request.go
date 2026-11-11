// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "time"

// Physical bounds are explicit assumptions for the complete selected period,
// not inventory speed estimates, financial commits or source ownership hints.
type CapacityPhysicalBound struct {
	ContextID   string `json:"context_id"`
	InterfaceID string `json:"interface_id"`
	MaxBPS      string `json:"max_bps"`
}

type CapacityBillRequest struct {
	Version        string                  `json:"version"`
	At             string                  `json:"at"`
	MaximumPollGap string                  `json:"maximum_poll_gap"`
	PhysicalBounds []CapacityPhysicalBound `json:"physical_bounds"`
	Invoiced       string                  `json:"invoiced,omitempty"`
}

type CapacityBillMember struct {
	ContextID         string    `json:"context_id"`
	DeviceID          string    `json:"device_id"`
	InterfaceID       string    `json:"interface_id"`
	IfIndex           uint32    `json:"if_index"`
	PhysicalMaxBPS    string    `json:"physical_max_bps"`
	ObservedNotBefore time.Time `json:"observed_not_before"`
}

type CapacityAgreementBill struct {
	Agreement        CapacityAgreement        `json:"agreement"`
	Period           CapacityBillingPeriod    `json:"period"`
	Members          []CapacityBillMember     `json:"members"`
	MaximumPollGap   string                   `json:"maximum_poll_gap"`
	Percentile       CapacityPercentileResult `json:"percentile"`
	Bill             CapacityBillResult       `json:"bill"`
	AsOf             time.Time                `json:"as_of"`
	SourceValidUntil time.Time                `json:"source_valid_until"`
	MembershipBasis  string                   `json:"membership_basis"`
}
