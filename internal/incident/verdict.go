// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import "time"

// FaultDomain is a deterministic evidence classification, independent of a
// remote model. RemoteService deliberately does not name a SaaS provider.
type FaultDomain string

const (
	FaultUnknown       FaultDomain = "unknown"
	FaultYourNetwork   FaultDomain = "your_network"
	FaultCarrier       FaultDomain = "carrier"
	FaultWiderInternet FaultDomain = "wider_internet"
	FaultRemoteService FaultDomain = "remote_service"
)

// VerdictCitation names an original observation, not a copied signal summary.
// Source readers must recheck the original document and current authority at
// publication; a citation is never a reusable grant.
type VerdictCitation struct {
	ContextID  string    `json:"context_id"`
	EntityID   string    `json:"entity_id"`
	EvidenceID string    `json:"evidence_id"`
	AgentID    string    `json:"agent_id"`
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
	Reason     string    `json:"reason"`
}

type VerdictHypothesis struct {
	Domain     FaultDomain       `json:"domain"`
	Confidence string            `json:"confidence"` // insufficient | corroborated | direct
	For        []VerdictCitation `json:"for"`
	Against    []VerdictCitation `json:"against"`
	Missing    []string          `json:"missing"`
}

// FaultVerdict preserves all hypotheses, including unavailable planes. A
// confidence is an evidence category, never a calibrated probability.
type FaultVerdict struct {
	Domain     FaultDomain         `json:"domain"`
	Confidence string              `json:"confidence"`
	Reason     string              `json:"reason"`
	From       time.Time           `json:"from"`
	To         time.Time           `json:"to"`
	Hypotheses []VerdictHypothesis `json:"hypotheses"`
}
