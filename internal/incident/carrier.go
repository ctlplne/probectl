// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/path"
)

const CarrierContractVersion = "probectl.carrier-ticket.v1"

// CarrierInput selects a window, never a tenant, source grant or membership.
type CarrierInput struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// CarrierPack is constructed from current authorized original-source reads.
// It carries no raw tenant field. Apply export redaction before signing it;
// portable bytes do not grant renewed online access to any cited source.
type CarrierPack struct {
	ContractVersion   string           `json:"contract_version"`
	IncidentID        string           `json:"incident_id"`
	GeneratedAt       time.Time        `json:"generated_at"`
	From              time.Time        `json:"from"`
	To                time.Time        `json:"to"`
	AddressesRedacted bool             `json:"addresses_redacted"`
	Summary           string           `json:"summary"`
	Interpretation    string           `json:"interpretation"`
	Coverage          CarrierCoverage  `json:"coverage"`
	Vantages          []CarrierVantage `json:"vantages"`
	Routing           []change.Event   `json:"routing"`
	Handoffs          []CarrierHandoff `json:"handoffs"`
}

type CarrierCoverage struct {
	Measurements string   `json:"measurements"`
	Traces       string   `json:"traces"`
	Routing      string   `json:"routing"`
	Handoffs     string   `json:"handoffs"`
	Missing      []string `json:"missing"`
}

type CarrierVantage struct {
	ContextID        string                  `json:"context_id"`
	EntityID         string                  `json:"entity_id"`
	TestID           string                  `json:"test_id"`
	AgentID          string                  `json:"agent_id"`
	DefinitionDigest string                  `json:"definition_digest"`
	Measurements     change.EffectTestPeriod `json:"measurements"`
	Traces           []CarrierTrace          `json:"traces"`
}

// Vantage names the actual tracing origin. Separate configured tests and
// probe agents do not turn control-plane traces into independent vantages.
type CarrierTrace struct {
	WindowCoverage       string     `json:"window_coverage"`
	RoundID              string     `json:"round_id"`
	ObservedAt           time.Time  `json:"observed_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	TrustedDiscoveryTime bool       `json:"trusted_discovery_time"`
	Vantage              string     `json:"vantage"`
	Path                 path.Path  `json:"path"`
}

type CarrierHandoff struct {
	ContextID       string                      `json:"context_id"`
	RouterID        string                      `json:"router_id"`
	InterfaceID     string                      `json:"interface_id"`
	AgentID         string                      `json:"agent_id"`
	SourceRef       string                      `json:"source_ref"`
	IfIndex         uint32                      `json:"if_index"`
	CurrentRole     string                      `json:"current_role"`
	RoleEvaluatedAt time.Time                   `json:"role_evaluated_at"`
	Coverage        string                      `json:"coverage"`
	Counters        []CarrierCounterObservation `json:"counters"`
}

// Counter values and uptime/discontinuity ticks remain exact decimal text.
// A gap, reset or missing field never becomes an observed zero or a rate.
type CarrierCounterObservation struct {
	Metric             string    `json:"metric"`
	Value              string    `json:"value"`
	Width              int       `json:"width"`
	PollStartedAt      time.Time `json:"poll_started_at"`
	PollCompletedAt    time.Time `json:"poll_completed_at"`
	CaptureKey         string    `json:"capture_key"`
	CaptureDigest      string    `json:"capture_digest"`
	UptimeKnown        bool      `json:"uptime_known"`
	UptimeTicks        string    `json:"uptime_ticks,omitempty"`
	DiscontinuityKnown bool      `json:"discontinuity_known"`
	DiscontinuityTicks string    `json:"discontinuity_ticks,omitempty"`
}
