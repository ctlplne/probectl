// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import "time"

type DependencyWorkflowCause struct {
	EntityID   string    `json:"entity_id"`
	IncidentID string    `json:"incident_id"`
	ObservedAt time.Time `json:"observed_at"`
	FreshUntil time.Time `json:"fresh_until"`
}

// DependencyWorkflow describes durable delivery bookkeeping checked against current source
// evidence. A pending decision is deliberately distinct from a published hold.
type DependencyWorkflow struct {
	State         string                    `json:"state"`
	Reason        string                    `json:"reason"`
	ContextID     string                    `json:"context_id,omitempty"`
	EntityID      string                    `json:"entity_id,omitempty"`
	EvidenceID    string                    `json:"evidence_id,omitempty"`
	ObservationID string                    `json:"observation_id,omitempty"`
	AsOf          *time.Time                `json:"as_of,omitempty"`
	FreshUntil    *time.Time                `json:"fresh_until,omitempty"`
	Causes        []DependencyWorkflowCause `json:"causes,omitempty"`
}
