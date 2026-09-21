// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"time"

	"github.com/ctlplne/probectl/internal/ai"
)

// The MCP tool result contract (Foundation-Loop S-063994f7).
//
// Every backend method used to return `any` — whatever struct the control plane
// had at hand — bounded only by a byte cap and a blanket string redaction of the
// encoded JSON. That is a WEAKER contract than the one the internal RCA path
// already enforces on itself, on the surface with the WEAKER trust: an MCP
// caller is an external AI client outside the operator's network.
//
// The weakness was structural, not accidental. `store.Test` carries TenantID and
// a free-form Params map; `incident.Signal` carries a free-form Attributes map;
// `Engine.Query` returns raw store rows (only Correlate reduced them). Adding a
// column to any of those tables published it to every MCP client, silently, with
// no code change anywhere near this package.
//
// These types are the fix: each one enumerates the fields that may cross, so the
// default for a new column is DROPPED. The one genuinely map-shaped payload —
// event rows — goes through ai.SanitizeRow, the same per-domain allow-list the
// RCA evidence path uses, so the two surfaces cannot drift apart.

// TestSummary is the published projection of a synthetic test. Deliberately
// absent: TenantID (the caller's own tenant, redundant and an isolation
// footgun if it ever disagreed) and Params (free-form per-type configuration
// that can carry targets, headers and credentials).
type TestSummary struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Target          string `json:"target"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	Enabled         bool   `json:"enabled"`
}

// TestsResult is the list_tests result.
type TestsResult struct {
	Tests     []TestSummary `json:"tests"`
	Limit     int           `json:"limit"`
	Truncated bool          `json:"truncated"`
}

// PathNode is one responder at one TTL. MPLS presence is published as a flag
// rather than as label stacks: an external model reasons about "this hop is
// MPLS-switched", and raw label values are operator infrastructure detail.
type PathNode struct {
	IP        string  `json:"ip"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
	LossRatio float64 `json:"loss_ratio"`
	RTTAvgMs  float64 `json:"rtt_avg_ms"`
	RTTMaxMs  float64 `json:"rtt_max_ms"`
	MPLS      bool    `json:"mpls"`
}

// PathHop is one TTL and the responders seen at it.
type PathHop struct {
	TTL   int        `json:"ttl"`
	Nodes []PathNode `json:"nodes"`
}

// PathResult is the get_path result. Deliberately absent: HopNode.Geo, which is
// operator-supplied location data about responders and is not needed to reason
// about a path.
type PathResult struct {
	Found              bool      `json:"found"`
	Target             string    `json:"target"`
	Mode               string    `json:"mode,omitempty"`
	DestinationReached bool      `json:"destination_reached,omitempty"`
	Hops               []PathHop `json:"hops,omitempty"`
}

// IncidentSignal is the published projection of one correlated signal.
// Deliberately absent: TenantID, and Attributes — a free-form per-plane map that
// any plane can add keys to without anyone reviewing this boundary.
type IncidentSignal struct {
	Plane      string    `json:"plane"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary,omitempty"`
	Target     string    `json:"target,omitempty"`
	Prefix     string    `json:"prefix,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// IncidentResult is the get_incident result.
type IncidentResult struct {
	ID               string           `json:"id"`
	Status           string           `json:"status"`
	Severity         string           `json:"severity"`
	Title            string           `json:"title"`
	Target           string           `json:"target,omitempty"`
	Prefix           string           `json:"prefix,omitempty"`
	StartedAt        time.Time        `json:"started_at"`
	LastSeenAt       time.Time        `json:"last_seen_at"`
	ResolvedAt       *time.Time       `json:"resolved_at,omitempty"`
	SignalCount      int              `json:"signal_count"`
	Signals          []IncidentSignal `json:"signals,omitempty"`
	SignalsTruncated bool             `json:"signals_truncated"`
	SignalsLimit     int              `json:"signals_limit,omitempty"`
}

// PlaneSignals is one plane's contribution to an incident. It is a LIST of
// named counts rather than a map keyed by plane name, so the result shape stays
// declared: a map's keys are data, and data must not decide the wire schema.
type PlaneSignals struct {
	Plane string `json:"plane"`
	Count int    `json:"count"`
}

// CorrelationResult is the correlate_incident result.
type CorrelationResult struct {
	Incident    IncidentResult `json:"incident"`
	Planes      []PlaneSignals `json:"planes"`
	SignalCount int            `json:"signal_count"`
}

// EventsResult is the get_bgp_events / query_flows result. Events are the one
// legitimately map-shaped payload — a row from the events store — so they are
// reduced by ai.SanitizeRow rather than by a struct.
type EventsResult struct {
	Events    []ai.Row `json:"events"`
	Truncated bool     `json:"truncated"`
	Note      string   `json:"note,omitempty"`
}

// ProposalResult is the propose_remediation result. Deliberately absent:
// TenantID. The state is always "proposed" on this path (§7.8) and is published
// so the model can see that it did NOT execute anything.
type ProposalResult struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title"`
	Rationale  string    `json:"rationale"`
	Target     string    `json:"target"`
	IncidentID string    `json:"incident_id,omitempty"`
	State      string    `json:"state"`
	ProposedBy string    `json:"proposed_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// SanitizeEventRows reduces raw store rows to the events-domain allow-list —
// the SAME list the RCA evidence path applies (internal/ai). Callers building an
// EventsResult must route rows through here; TestMCPEventRowsPassTheSharedFieldAllowList
// asserts an unlisted key does not survive.
func SanitizeEventRows(rows []ai.Row) []ai.Row {
	out := make([]ai.Row, 0, len(rows))
	for _, row := range rows {
		out = append(out, ai.SanitizeRow(ai.DomainEvents, row))
	}
	return out
}
