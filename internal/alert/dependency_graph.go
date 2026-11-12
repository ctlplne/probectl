// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

// DependencyGraphInput is explicit operator intent on the existing alert
// policy. Its IDs are references, never evidence or authorization. Every use
// resolves them against current canonical entities, assignments and sources.
// Physical adjacency and address similarity cannot manufacture these edges.
type DependencyGraphInput struct {
	Nodes []DependencyNodeInput `json:"nodes"`
}

type DependencyNodeInput struct {
	EntityID string   `json:"entity_id"`
	AgentID  string   `json:"agent_id"`
	TestID   string   `json:"test_id"`
	Parents  []string `json:"parents"`
}

// Validate checks completeness and acyclicity iteratively, without a depth or
// population ceiling. Request/operation memory and deadlines admit the complete
// graph. Connected sources must share a vantage; a CP trace or another agent's
// failure cannot establish the path used by this agent's downstream probes.
func (graph *DependencyGraphInput) Validate() error {
	if graph == nil {
		return nil // existing context-only policy remains inactive
	}
	if len(graph.Nodes) == 0 {
		return ErrDependencyEvidence
	}
	nodes := make(map[string]DependencyNodeInput, len(graph.Nodes))
	sources := make(map[string]bool, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if !canonicalQueryID(node.EntityID) || !canonicalQueryID(node.AgentID) || !canonicalQueryID(node.TestID) || node.Parents == nil {
			return ErrDependencyEvidence
		}
		if _, duplicate := nodes[node.EntityID]; duplicate || sources[node.AgentID+":"+node.TestID] {
			return ErrDependencyEvidence
		}
		nodes[node.EntityID] = node
		sources[node.AgentID+":"+node.TestID] = true
	}
	remaining := make(map[string]int, len(nodes))
	children := make(map[string][]string)
	queue := make([]string, 0)
	for _, node := range graph.Nodes {
		parents := make(map[string]bool, len(node.Parents))
		for _, parentID := range node.Parents {
			parent, exists := nodes[parentID]
			if !exists || parentID == node.EntityID || parents[parentID] || parent.AgentID != node.AgentID {
				return ErrDependencyEvidence
			}
			parents[parentID] = true
			children[parentID] = append(children[parentID], node.EntityID)
		}
		remaining[node.EntityID] = len(node.Parents)
		if len(node.Parents) == 0 {
			queue = append(queue, node.EntityID)
		}
	}
	visited := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		visited++
		for _, child := range children[id] {
			remaining[child]--
			if remaining[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	if visited != len(nodes) {
		return ErrDependencyEvidence
	}
	return nil
}
