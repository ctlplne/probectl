// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	dependencyTenantA = "11111111-1111-4111-8111-111111111111"
	dependencyTenantB = "22222222-2222-4222-8222-222222222222"
	dependencyContext = "33333333-3333-4333-8333-333333333333"
	dependencyRoot    = "44444444-4444-4444-8444-444444444444"
	dependencyRouter  = "55555555-5555-4555-8555-555555555555"
	dependencyTarget  = "66666666-6666-4666-8666-666666666666"
	dependencyBackup  = "77777777-7777-4777-8777-777777777777"
	dependencyRoom    = "88888888-8888-4888-8888-888888888888"
)

func dependencyFixture(tenant string) dependencySnapshot {
	at := time.Now().UTC()
	fresh := at.Add(time.Minute)
	return dependencySnapshot{TenantID: tenant, ContextID: dependencyContext, At: at, Complete: true,
		Vertices: []dependencyVertex{
			{EntityID: dependencyRoot, FreshUntil: fresh},
			{EntityID: dependencyRouter, Parents: []string{dependencyRoot}, FreshUntil: fresh},
			{EntityID: dependencyTarget, Parents: []string{dependencyRouter}, FreshUntil: fresh},
		},
		Causes: []dependencyCause{{TenantID: tenant, ContextID: dependencyContext, EntityID: dependencyRouter, IncidentID: dependencyRoom, ObservedAt: at.Add(-time.Second), FreshUntil: fresh}},
	}
}

func TestTopologyDependencySelectionHoldsOnlyACompleteFailedCutAndReleases(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(dependencyTenantA))
	graph := dependencyFixture(dependencyTenantA)
	budget := dependencyBudget{memory: 1 << 20, work: 1 << 20}
	held, err := selectDependencyHold(ctx, graph, dependencyTarget, true, budget)
	if err != nil || !held.Held || len(held.Causes) != 1 || held.Causes[0].IncidentID != dependencyRoom || held.Reason == "" || !held.At.Equal(graph.At) {
		t.Fatal("actual complete failed parent cut did not identify its incident", held, err)
	}
	independent, err := selectDependencyHold(ctx, graph, dependencyTarget, false, budget)
	if err != nil || independent.Held || len(independent.Causes) != 0 {
		t.Fatal("independent downstream symptom was held", independent, err)
	}
	upstream, err := selectDependencyHold(ctx, graph, dependencyRouter, true, budget)
	if err != nil || upstream.Held || len(upstream.Causes) != 0 {
		t.Fatal("upstream failure suppressed its own notification", upstream, err)
	}
	graph.Vertices = append(graph.Vertices, dependencyVertex{EntityID: dependencyBackup, FreshUntil: graph.At.Add(time.Minute)})
	graph.Vertices[2].Parents = append(graph.Vertices[2].Parents, dependencyBackup)
	backup, err := selectDependencyHold(ctx, graph, dependencyTarget, true, budget)
	if err != nil || backup.Held || len(backup.Causes) != 0 {
		t.Fatal("a current alternative path was hidden", backup, err)
	}
	graph.Causes = append(graph.Causes, dependencyCause{TenantID: graph.TenantID, ContextID: graph.ContextID, EntityID: dependencyBackup, IncidentID: dependencyRoom, ObservedAt: graph.At, FreshUntil: graph.At.Add(time.Minute)})
	both, err := selectDependencyHold(ctx, graph, dependencyTarget, true, budget)
	if err != nil || !both.Held || len(both.Causes) != 2 || both.Causes[0].EntityID >= both.Causes[1].EntityID {
		t.Fatal("redundant failed parents lost the complete deterministic cause set", both, err)
	}
	graph.Causes = nil
	recovered, err := selectDependencyHold(ctx, graph, dependencyTarget, true, budget)
	if err != nil || recovered.Held || len(recovered.Causes) != 0 {
		t.Fatal("recovered upstream retained a previous hold", recovered, err)
	}
}

func TestTopologyDependencySelectionRequiresCurrentTenantAndCompleteEvidence(t *testing.T) {
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		budget := dependencyBudget{memory: 1 << 20, work: 1 << 20}
		own := dependencyFixture(tenant)
		if out, err := selectDependencyHold(ctx, own, dependencyTarget, true, budget); err != nil || !out.Held || out.Causes[0].TenantID != tenant {
			t.Fatal("overlapping canonical identity crossed its tenant domain", out, err)
		}
		for _, mutate := range []func(*dependencySnapshot){
			func(g *dependencySnapshot) { g.TenantID = "99999999-9999-4999-8999-999999999999" },
			func(g *dependencySnapshot) { g.Causes[0].TenantID = "99999999-9999-4999-8999-999999999999" },
			func(g *dependencySnapshot) { g.Causes[0].ContextID = dependencyRoom },
			func(g *dependencySnapshot) { g.Complete = false },
			func(g *dependencySnapshot) { g.Vertices[1].FreshUntil = g.At.Add(-time.Second) },
			func(g *dependencySnapshot) { g.Vertices[1].FreshUntil = g.At },
			func(g *dependencySnapshot) { g.Causes[0].FreshUntil = g.At.Add(-time.Second) },
			func(g *dependencySnapshot) { g.Causes[0].FreshUntil = g.At },
			func(g *dependencySnapshot) { g.Vertices[0].Parents = []string{dependencyTarget} },
			func(g *dependencySnapshot) { g.Vertices[1].Parents = []string{dependencyBackup} },
		} {
			changed := dependencyFixture(tenant)
			mutate(&changed)
			if out, err := selectDependencyHold(ctx, changed, dependencyTarget, true, budget); err == nil || !reflect.DeepEqual(out, dependencySelection{}) {
				t.Fatal("foreign/stale/incomplete dependency evidence published a hold", out, err)
			}
		}
		if out, err := selectDependencyHold(ctx, own, dependencyTarget, true, dependencyBudget{memory: 1, work: 1}); err == nil || !reflect.DeepEqual(out, dependencySelection{}) {
			t.Fatal("refused admission returned partial routing authority", out, err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if out, err := selectDependencyHold(canceled, own, dependencyTarget, true, budget); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, dependencySelection{}) {
			t.Fatal("canceled current read published a hold", out, err)
		}
	}
}

// selectDependencyHold preserves the single-decision door for callers which
// do not evaluate a population. The production router prepares once per batch.
func selectDependencyHold(ctx context.Context, graph dependencySnapshot, target string, reachabilitySymptom bool, budget dependencyBudget) (dependencySelection, error) {
	p, err := prepareDependencyGraph(ctx, graph, budget)
	if err != nil {
		return dependencySelection{}, err
	}
	return p.selectHold(ctx, target, reachabilitySymptom)
}
