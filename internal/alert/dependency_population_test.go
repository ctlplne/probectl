// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDependencyPopulationPreservesEverySeriesAndNearestCause(t *testing.T) {
	// This is the complete configured population, not a sample of leaves. A
	// single operation budget must admit all decisions, including deep chains.
	const population = 20_000
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		at := time.Now().UTC()
		graph := DependencySnapshot{TenantID: tenant, ContextID: dependencyContext, At: at, Complete: true}
		for i := range population {
			id := fmt.Sprintf("%08x-1111-4111-8111-111111111111", i+1)
			var parents []string
			if i > 0 {
				parents = []string{graph.Vertices[i-1].EntityID}
			}
			graph.Vertices = append(graph.Vertices, DependencyVertex{EntityID: id, Parents: parents, FreshUntil: at.Add(time.Minute)})
			graph.Causes = append(graph.Causes, DependencyCause{TenantID: tenant, ContextID: dependencyContext, EntityID: id,
				IncidentID: fmt.Sprintf("%08x-2222-4222-8222-222222222222", i+1), ObservedAt: at, FreshUntil: at.Add(time.Minute)})
		}
		decider, err := PrepareDependencyNotifications(ctx, graph, 192<<20, 192<<20)
		if err != nil {
			t.Fatal(err)
		}
		for i, vertex := range graph.Vertices {
			attempt := DependencyAttempt{Alert: Alert{TenantID: tenant, RuleID: dependencyRoom, State: StateFiring,
				Labels: map[string]string{"test_id": vertex.EntityID}}, RuleUpdatedAt: at}
			decision, err := decider.Decide(ctx, attempt, vertex.EntityID, true)
			if err != nil || decision.Held() != (i > 0) || !decision.matches(attempt.Alert, at) {
				t.Fatalf("tenant=%s series=%d: incomplete or incorrect decision: %v", tenant, i, err)
			}
			causes := decision.Causes()
			if i > 0 && (len(causes) != 1 || causes[0] != graph.Causes[i-1]) {
				t.Fatalf("series %d lost its nearest current cause: %+v", i, causes)
			}
			if i == 0 && len(causes) != 0 {
				t.Fatal("root suppressed its own notification")
			}
		}
	}
}

func TestDependencyPopulationCannotBorrowOrMutatePreparedAuthority(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(dependencyTenantA))
	graph := dependencyFixture(dependencyTenantA)
	decider, err := PrepareDependencyNotifications(ctx, graph, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Input and returned slices must not rewrite later series' routing evidence.
	graph.Vertices[2].Parents[0] = dependencyRoot
	graph.Causes[0].TenantID = dependencyTenantB
	attempt := DependencyAttempt{Alert: Alert{TenantID: dependencyTenantA, RuleID: dependencyRoom, State: StateFiring}}
	first, err := decider.Decide(ctx, attempt, dependencyTarget, true)
	if err != nil || !first.Held() {
		t.Fatal("input mutation changed prepared evidence", err)
	}
	causes := first.Causes()
	causes[0].TenantID = dependencyTenantB
	second, err := decider.Decide(ctx, attempt, dependencyTarget, true)
	if err != nil || !second.Held() || second.Causes()[0].TenantID != dependencyTenantA {
		t.Fatal("returned cause mutation changed current authority", err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID(dependencyTenantB))
	if decision, err := decider.Decide(foreign, attempt, dependencyTarget, true); err == nil || decision.Held() {
		t.Fatal("prepared authority crossed its tenant")
	}
	if decision, err := decider.Decide(ctx, attempt, dependencyBackup, true); err == nil || decision.Held() {
		t.Fatal("unknown target borrowed another cut")
	}
	// Exhaust the complete operation, not a newly reset budget per series.
	decider.graph.budget = dependencyBudget{memory: 1, work: 1}
	if decision, err := decider.Decide(ctx, attempt, dependencyTarget, true); !errors.Is(err, ErrDependencyBudget) || decision.Held() {
		t.Fatal("shared admission returned partial hold authority", err)
	}
}
