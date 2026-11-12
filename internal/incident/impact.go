// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import "time"

// ImpactInput contains selections only; membership and source authority come
// from current tenant storage, not user-supplied entity/address lists.
type ImpactInput struct {
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	DataSeries     string    `json:"dataseries,omitempty"`
	CustomerTagKey string    `json:"customer_tag_key,omitempty"`
}

// Counter strings preserve raw and sampling-adjusted values beyond uint64
// and JavaScript's integer range. Sampling describes an estimate, not proof
// that every packet in the network was observed.
type ImpactCounters struct {
	RawBytes      string `json:"raw_bytes"`
	RawPackets    string `json:"raw_packets"`
	ScaledBytes   string `json:"scaled_bytes"`
	ScaledPackets string `json:"scaled_packets"`
}

type ImpactCaptureCitation struct {
	Key              string    `json:"key"`
	CapturedAt       time.Time `json:"captured_at"`
	ContextID        string    `json:"context_id"`
	RouterID         string    `json:"router_id"`
	OriginalSourceID string    `json:"original_source_id"`
	CurrentSourceID  string    `json:"current_source_id"`
}

type ImpactPeriod struct {
	From              time.Time               `json:"from"`
	To                time.Time               `json:"to"`
	AttestedRecords   int                     `json:"attested_records"`
	UnverifiedRecords int                     `json:"unverified_records"`
	Coverage          string                  `json:"coverage"`
	ObservedTotals    *ImpactCounters         `json:"observed_totals,omitempty"`
	Captures          []ImpactCaptureCitation `json:"captures"`
}

type ImpactMember struct {
	ContextID    string   `json:"context_id"`
	EntityID     string   `json:"entity_id"`
	Kind         string   `json:"kind,omitempty"`
	IncidentRoot bool     `json:"incident_root"`
	SignalIDs    []string `json:"signal_ids"`
	Reason       string   `json:"reason"`
	SourceIDs    []string `json:"source_ids"`
}

type ImpactCustomer struct {
	TagKey      string          `json:"tag_key"`
	Value       string          `json:"value"`
	ContextID   string          `json:"context_id"`
	PrefixIDs   []string        `json:"prefix_ids"`
	TestIDs     []string        `json:"test_ids"`
	SLOIDs      []string        `json:"slo_ids"`
	CaptureKeys []string        `json:"capture_keys"`
	Current     *ImpactCounters `json:"current_observed_totals,omitempty"`
	Previous    *ImpactCounters `json:"previous_observed_totals,omitempty"`
}

type ImpactResponse struct {
	ContractVersion     string           `json:"contract_version"`
	Preview             bool             `json:"preview"`
	IncidentID          string           `json:"incident_id"`
	EvaluatedAt         time.Time        `json:"evaluated_at"`
	ValidUntil          *time.Time       `json:"valid_until,omitempty"`
	Current             ImpactPeriod     `json:"current"`
	Previous            ImpactPeriod     `json:"previous"`
	Members             []ImpactMember   `json:"members"`
	UnresolvedRoot      bool             `json:"unresolved_root"`
	UnresolvedSignalIDs []string         `json:"unresolved_signal_ids"`
	Customers           []ImpactCustomer `json:"customers"`
	CustomerCoverage    string           `json:"customer_coverage"`
	CustomerTagRevision int64            `json:"customer_tag_revision,omitempty"`
	UnclassifiedRecords int              `json:"unclassified_records"`
	ObservedByteChange  string           `json:"observed_scaled_byte_change,omitempty"`
	Interpretation      string           `json:"interpretation"`
}
