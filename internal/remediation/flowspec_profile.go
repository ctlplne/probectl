// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

type FlowSpecRouterProfile string

const (
	FlowSpecJunosStandard FlowSpecRouterProfile = "junos_standard"
	FlowSpecIOSXR711      FlowSpecRouterProfile = "ios_xr_asr9000_7_11"
	FlowSpecEOS436        FlowSpecRouterProfile = "eos_4_36_2f"
	FlowSpecFRR1071       FlowSpecRouterProfile = "frr_10_7_1"
)

type FlowSpecQualificationInput struct {
	Profile          FlowSpecRouterProfile `json:"profile"`
	RoutingTable     string                `json:"routing_table"`
	AvailableEntries *uint32               `json:"available_entries,omitempty"`
}

type FlowSpecComponent struct {
	Type  uint8  `json:"type"`
	Field string `json:"field"`
	Value string `json:"value"`
}

type FlowSpecRuleTemplate struct {
	AFI        uint16              `json:"afi"`
	SAFI       uint8               `json:"safi"`
	Components []FlowSpecComponent `json:"components"`
	Action     string              `json:"action"`
}

type FlowSpecQualification struct {
	ReviewFingerprint string                  `json:"review_fingerprint"`
	Profile           FlowSpecRouterProfile   `json:"profile"`
	RoutingTable      string                  `json:"routing_table"`
	AddressFamily     string                  `json:"address_family"`
	SyntaxCompatible  bool                    `json:"syntax_compatible"`
	Capacity          FlowSpecProfileCapacity `json:"capacity"`
	Documentation     string                  `json:"documentation"`
	Findings          []string                `json:"findings"`
	Template          *FlowSpecRuleTemplate   `json:"template,omitempty"`
}

type FlowSpecProfileCapacity struct {
	MinimumEntries  uint32  `json:"minimum_entries"`
	DeclaredEntries *uint32 `json:"declared_entries,omitempty"`
	FitsDeclared    *bool   `json:"fits_declared,omitempty"`
}
