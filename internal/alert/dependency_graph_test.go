// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"fmt"
	"testing"
)

func TestDependencyGraphKeepsCompleteCanonicalSingleVantagePaths(t *testing.T) {
	base := func() *DependencyGraphInput {
		return &DependencyGraphInput{Nodes: []DependencyNodeInput{
			{EntityID: dependencyRoot, AgentID: dependencyRoom, TestID: dependencyRoot, Parents: []string{}},
			{EntityID: dependencyRouter, AgentID: dependencyRoom, TestID: dependencyRouter, Parents: []string{dependencyRoot}},
			{EntityID: dependencyTarget, AgentID: dependencyRoom, TestID: dependencyTarget, Parents: []string{dependencyRouter, dependencyRoot}},
		}}
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*DependencyGraphInput){
		func(g *DependencyGraphInput) { g.Nodes = nil },
		func(g *DependencyGraphInput) { g.Nodes[0].EntityID = "10.0.0.1" },
		func(g *DependencyGraphInput) { g.Nodes[0].AgentID = "agent-label" },
		func(g *DependencyGraphInput) { g.Nodes[0].Parents = nil },
		func(g *DependencyGraphInput) { g.Nodes[0].Parents = []string{dependencyTarget} },
		func(g *DependencyGraphInput) { g.Nodes[1].Parents = []string{dependencyBackup} },
		func(g *DependencyGraphInput) { g.Nodes[1].Parents = []string{dependencyRoot, dependencyRoot} },
		func(g *DependencyGraphInput) { g.Nodes[1].AgentID = dependencyBackup },
		func(g *DependencyGraphInput) { g.Nodes[1].TestID = dependencyRoot },
		func(g *DependencyGraphInput) { g.Nodes[1].EntityID = dependencyRoot },
	} {
		graph := base()
		mutate(graph)
		if err := graph.Validate(); err == nil {
			t.Fatal("incomplete/conflicting graph authorized a dependency", graph)
		}
	}
	deep := &DependencyGraphInput{}
	for i := range 20000 {
		id := fmt.Sprintf("%08x-0000-4000-8000-000000000001", i+1)
		node := DependencyNodeInput{EntityID: id, AgentID: dependencyRoom, TestID: id, Parents: []string{}}
		if i > 0 {
			node.Parents = []string{deep.Nodes[i-1].EntityID}
		}
		deep.Nodes = append(deep.Nodes, node)
	}
	if err := deep.Validate(); err != nil {
		t.Fatal("a complete deep graph was capped", err)
	}
}
