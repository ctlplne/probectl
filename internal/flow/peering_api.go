// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "time"

// PeeringEstimateInput contains only user selections. Tenant, router ownership,
// source identity, classifications and observed coverage are server-derived.
type PeeringEstimateInput struct {
	ContextID     string    `json:"context_id"`
	InterfaceID   string    `json:"interface_id"`
	PeerASN       uint32    `json:"peer_asn"`
	IXID          string    `json:"ix_id"`
	LANID         string    `json:"ix_lan_id"`
	Direction     string    `json:"direction"`
	From          time.Time `json:"from,omitempty"`
	To            time.Time `json:"to,omitempty"`
	BucketSeconds int       `json:"bucket_seconds,omitempty"`
	DataSeries    string    `json:"dataseries,omitempty"`
}

type PeeringEstimateTarget struct {
	ContextID     string     `json:"context_id"`
	InterfaceID   string     `json:"interface_id"`
	RouterID      string     `json:"router_id,omitempty"`
	PeerASN       uint32     `json:"peer_asn"`
	IXID          string     `json:"ix_id"`
	LANID         string     `json:"ix_lan_id"`
	Eligible      bool       `json:"eligible"`
	Reason        string     `json:"reason"`
	AsOf          *time.Time `json:"as_of,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
	PrefixVersion string     `json:"prefix_version,omitempty"`
	MemberVersion string     `json:"membership_version,omitempty"`
	PrefixIDs     []string   `json:"prefix_sources"`
	MemberIDs     []string   `json:"membership_sources"`
}

type PeeringEstimateCoverage struct {
	ObservedIntervals      int   `json:"observed_intervals"`
	ExpectedIntervals      int64 `json:"expected_intervals"`
	CompleteObservedInputs bool  `json:"complete_observed_inputs"`
	CompleteClassification bool  `json:"complete_routing_classification"`
}

// Decimal strings retain exact values through JSON and JavaScript clients.
type PeeringRateEstimate struct {
	SelectedIntervalBytes    string `json:"selected_interval_bytes"`
	BitsPerSecondNumerator   string `json:"bits_per_second_numerator"`
	BitsPerSecondDenominator string `json:"bits_per_second_denominator"`
	Intervals                int    `json:"intervals"`
	Rank                     int    `json:"rank"`
	Nonzero                  int    `json:"nonzero_intervals"`
}

type PeeringTransitEstimate struct {
	InterfaceID string              `json:"interface_id"`
	P95         PeeringRateEstimate `json:"known_eligible_p95"`
}

type PeeringEstimateResponse struct {
	ContractVersion string                   `json:"contract_version"`
	Preview         bool                     `json:"preview"`
	Target          PeeringEstimateTarget    `json:"target"`
	Direction       string                   `json:"direction"`
	Reason          string                   `json:"reason"`
	From            time.Time                `json:"from"`
	To              time.Time                `json:"to"`
	BucketSeconds   int                      `json:"bucket_seconds"`
	Source          string                   `json:"source,omitempty"`
	Coverage        PeeringEstimateCoverage  `json:"coverage"`
	Bytes           map[string]string        `json:"bytes"`
	P95             *PeeringRateEstimate     `json:"known_eligible_p95,omitempty"`
	Transit         []PeeringTransitEstimate `json:"transit"`
	Interpretation  string                   `json:"interpretation"`
}
