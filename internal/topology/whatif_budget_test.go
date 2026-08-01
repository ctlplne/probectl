// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package topology

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// buildWideGraph creates a graph with `agents` agents, each reaching `hosts`
// hosts through a shared aggregation hop — the shape whose per-agent BFS makes
// what-if superlinear.
func buildWideGraph(t *testing.T, agents, hosts int) Store {
	t.Helper()
	s := NewIndexedStore()
	for a := 0; a < agents; a++ {
		agent := fmt.Sprintf("agent-%d", a)
		for h := 0; h < hosts; h++ {
			s.ObservePath("t1", PathInput{
				AgentID:  agent,
				Target:   fmt.Sprintf("svc-%d", h),
				TargetIP: fmt.Sprintf("203.0.113.%d", h%250+1),
				Hops:     []string{"10.0.0.1", fmt.Sprintf("10.0.1.%d", h%250+1)},
			}, time.Now())
		}
	}
	return s
}

// TestWhatIfRespectsAgentBoundAndDegradesHonestly is S-29804e53's proof: with
// a budget smaller than the graph, the simulation STOPS at the bound and says
// so, instead of running the full per-agent BFS on a synchronous handler.
func TestWhatIfRespectsAgentBoundAndDegradesHonestly(t *testing.T) {
	s := buildWideGraph(t, 40, 20)

	full, err := SimulateWithBudget(s, "t1", "hop:10.0.0.1", time.Time{}, nil,
		Budget{MaxAgents: 1000, MaxVisits: 10_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if full.Partial {
		t.Fatalf("a generous budget must produce a COMPLETE result, got partial: %v", full.Coverage.Notes)
	}

	bounded, err := SimulateWithBudget(s, "t1", "hop:10.0.0.1", time.Time{}, nil,
		Budget{MaxAgents: 3, MaxVisits: 10_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if !bounded.Partial {
		t.Fatal("a budget below the agent count must yield a PARTIAL result")
	}
	// The bound must be enforced at the agent LOOP, so the impact it reports
	// can only ever be a subset of the complete run's.
	if len(bounded.Disconnected) > len(full.Disconnected) {
		t.Fatalf("the bounded run reported MORE disconnections (%d) than the complete one (%d) — the bound is not a truncation",
			len(bounded.Disconnected), len(full.Disconnected))
	}
	var noted bool
	for _, n := range bounded.Coverage.Notes {
		if strings.Contains(n, "PARTIAL RESULT") && strings.Contains(n, "agent budget") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("a truncated simulation must NAME the bound it hit: %v", bounded.Coverage.Notes)
	}
}

// TestWhatIfRespectsVisitBound: the node-visit budget is the bound that
// actually tracks cost on a dense graph, and it must also degrade honestly.
func TestWhatIfRespectsVisitBound(t *testing.T) {
	s := buildWideGraph(t, 30, 30)
	imp, err := SimulateWithBudget(s, "t1", "hop:10.0.0.1", time.Time{}, nil,
		Budget{MaxAgents: 10_000, MaxVisits: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !imp.Partial {
		t.Fatal("a 5-visit budget must truncate a 30-agent graph")
	}
}

// TestWhatIfAtGraphMaximaStaysInsideBudget is the load assertion: a graph at
// the documented maxima completes inside the DEFAULT budget's wall clock, so
// the served handler cannot be held open by an ordinary tenant.
func TestWhatIfAtGraphMaximaStaysInsideBudget(t *testing.T) {
	s := buildWideGraph(t, 200, 50)
	budget := DefaultBudget()

	start := time.Now()
	imp, err := SimulateWithBudget(s, "t1", "hop:10.0.0.1", time.Time{}, nil, budget)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > budget.Deadline {
		t.Fatalf("simulation took %s, beyond the declared %s budget", elapsed, budget.Deadline)
	}
	t.Logf("what-if over 200 agents x 50 hosts: %s (partial=%t, budget %s)", elapsed, imp.Partial, budget.Deadline)
}

// TestWhatIfDefaultBudgetIsBounded: the defaults must actually bound something
// — a zero budget would make every field above meaningless.
func TestWhatIfDefaultBudgetIsBounded(t *testing.T) {
	b := DefaultBudget()
	if b.MaxAgents <= 0 || b.MaxVisits <= 0 || b.Deadline <= 0 {
		t.Fatalf("the default budget must bound agents, visits AND wall clock: %+v", b)
	}
	// Zero values must normalize to the defaults rather than to "unbounded".
	n := Budget{}.normalized()
	if n.MaxAgents != b.MaxAgents || n.MaxVisits != b.MaxVisits {
		t.Fatalf("zero budget normalized to %+v, want the defaults %+v", n, b)
	}
}
