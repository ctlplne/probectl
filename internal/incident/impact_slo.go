// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

type ImpactSLOSource struct {
	ContextID   string   `json:"context_id"`
	EntityID    string   `json:"entity_id"`
	TestID      string   `json:"test_id"`
	AgentID     string   `json:"agent_id"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type ImpactSLOPeriod struct {
	FailedInputs int               `json:"failed_inputs"`
	Sources      []ImpactSLOSource `json:"sources"`
}

// Names are OpenSLO names, not UUIDs. Only cited failed executions contribute
// to these periods; configuration alone does not establish measured impact.
type ImpactSLO struct {
	Name             string          `json:"name"`
	DisplayName      string          `json:"display_name"`
	Service          string          `json:"service"`
	DefinitionDigest string          `json:"definition_digest"`
	ObjectiveRatio   string          `json:"objective_ratio"`
	Window           string          `json:"window"`
	Basis            string          `json:"basis"`
	Current          ImpactSLOPeriod `json:"current"`
	Previous         ImpactSLOPeriod `json:"previous"`
}
