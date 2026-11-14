// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/flow"
)

// Only selectors verified against live tenant-composite references reach this
// projection. Canonical UUIDs use the existing metadata renderer; opaque agent
// strings, operator terms and prices still traverse full text/PII redaction.
func nativeCarrierSLATerms(terms flow.CarrierSLATerms) any {
	type source struct {
		Agent any                `json:"agent_id"`
		Test  mcp.NativeRoleUUID `json:"test_id"`
	}
	out := struct {
		flow.CarrierSLATerms
		Sources []source `json:"sources,omitempty"`
	}{CarrierSLATerms: terms, Sources: make([]source, 0, len(terms.Sources))}
	for _, item := range terms.Sources {
		var agent any = item.AgentID
		canonical := mcp.NativeRoleUUID(item.AgentID)
		if _, err := json.Marshal(canonical); err == nil {
			agent = canonical
		}
		out.Sources = append(out.Sources, source{Agent: agent, Test: mcp.NativeRoleUUID(item.TestID)})
	}
	return out
}
