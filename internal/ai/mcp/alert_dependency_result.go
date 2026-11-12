// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"time"

	"github.com/ctlplne/probectl/internal/alert"
)

// Only the shared backend's authorized canonical configuration references use
// metadata encoding. No target, sender evidence or free text is exempted from
// the existing egress redaction floor. JSON values and the public shape stay
// identical to REST, including an explicit empty parents array for each root.
type nativeDependencyNode struct {
	EntityID NativeRoleUUID   `json:"entity_id"`
	AgentID  NativeRoleUUID   `json:"agent_id"`
	TestID   NativeRoleUUID   `json:"test_id"`
	Parents  []NativeRoleUUID `json:"parents"`
}

type nativeDependencyGraph struct {
	Nodes []nativeDependencyNode `json:"nodes"`
}

type nativeDependencyPolicy struct {
	ContextID        NativeRoleUUID         `json:"context_id"`
	FreshnessSeconds int64                  `json:"freshness_seconds"`
	Graph            *nativeDependencyGraph `json:"graph,omitempty"`
}

type nativeDependencyState struct {
	RuleID        NativeRoleUUID          `json:"rule_id"`
	RuleUpdatedAt time.Time               `json:"rule_updated_at"`
	Configured    bool                    `json:"configured"`
	Policy        *nativeDependencyPolicy `json:"policy,omitempty"`
}

func dependencyNativeResult(state alert.DependencyPolicyState, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	out := nativeDependencyState{RuleID: NativeRoleUUID(state.RuleID), RuleUpdatedAt: state.RuleUpdatedAt, Configured: state.Configured}
	if state.Policy == nil {
		return out, nil
	}
	out.Policy = &nativeDependencyPolicy{ContextID: NativeRoleUUID(state.Policy.ContextID), FreshnessSeconds: state.Policy.FreshnessSeconds}
	if state.Policy.Graph != nil {
		graph := &nativeDependencyGraph{Nodes: make([]nativeDependencyNode, len(state.Policy.Graph.Nodes))}
		for i, node := range state.Policy.Graph.Nodes {
			native := nativeDependencyNode{EntityID: NativeRoleUUID(node.EntityID), AgentID: NativeRoleUUID(node.AgentID), TestID: NativeRoleUUID(node.TestID)}
			if node.Parents != nil {
				native.Parents = make([]NativeRoleUUID, len(node.Parents))
				for j, parent := range node.Parents {
					native.Parents[j] = NativeRoleUUID(parent)
				}
			}
			graph.Nodes[i] = native
		}
		out.Policy.Graph = graph
	}
	return out, nil
}

type nativeDependencyWorkflowCause struct {
	EntityID   NativeRoleUUID `json:"entity_id"`
	IncidentID NativeRoleUUID `json:"incident_id"`
	ObservedAt time.Time      `json:"observed_at"`
	FreshUntil time.Time      `json:"fresh_until"`
}

type nativeDependencyWorkflow struct {
	State         string                          `json:"state"`
	Reason        string                          `json:"reason"`
	ContextID     NativeRoleUUID                  `json:"context_id,omitempty"`
	EntityID      NativeRoleUUID                  `json:"entity_id,omitempty"`
	EvidenceID    NativeRoleUUID                  `json:"evidence_id,omitempty"`
	ObservationID NativeRoleUUID                  `json:"observation_id,omitempty"`
	AsOf          *time.Time                      `json:"as_of,omitempty"`
	FreshUntil    *time.Time                      `json:"fresh_until,omitempty"`
	Causes        []nativeDependencyWorkflowCause `json:"causes,omitempty"`
}

func dependencyWorkflowNativeResult(state *alert.DependencyWorkflow, err error) (any, error) {
	if err != nil || state == nil {
		return nil, err
	}
	out := nativeDependencyWorkflow{State: state.State, Reason: state.Reason, ContextID: NativeRoleUUID(state.ContextID), EntityID: NativeRoleUUID(state.EntityID),
		EvidenceID: NativeRoleUUID(state.EvidenceID), ObservationID: NativeRoleUUID(state.ObservationID), AsOf: state.AsOf, FreshUntil: state.FreshUntil}
	for _, cause := range state.Causes {
		out.Causes = append(out.Causes, nativeDependencyWorkflowCause{EntityID: NativeRoleUUID(cause.EntityID), IncidentID: NativeRoleUUID(cause.IncidentID), ObservedAt: cause.ObservedAt, FreshUntil: cause.FreshUntil})
	}
	return out, nil
}
