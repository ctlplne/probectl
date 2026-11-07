// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags(t *testing.T) {
	f, rows, actors, at := newRoleFlowQueryFixture(t)
	// Use the shipped native backend; the mutation wrapper belongs to another
	// proof and is intentionally not a supported report batch implementation.
	f.server.WithFlowStore(rows.Memory).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.pool, 0, audit.TenantRecord))
	captures := map[string]*reportFlowCapture{}
	for _, tenant := range f.tenants {
		ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actors[tenant])
		ctx, err := f.server.withFlowViewVocabulary(ctx, actors[tenant])
		if err != nil {
			t.Fatal(err)
		}
		view, err := views.SaveQueryView(ctx, tenant, actors[tenant].UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Canonical role report", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), DataSeries: "raw", GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		capture, err := f.server.captureReportFlowSources(ctx, actors[tenant], []reportFlowSourceRef{{ID: view.ID, Version: view.Version}})
		if err != nil {
			t.Fatal("role-only report could not capture its admitted sources", err)
		}
		t.Cleanup(capture.Close)
		if !capture.ContextSources || !capture.ContextsCaptured || len(capture.Contexts) != 1 || capture.Contexts[0].ContextID != f.contextID || capture.Contexts[0].Resource[auth.ResourceTenantKey] != tenant {
			t.Fatal("role-only report lost complete canonical source context")
		}
		raw, err := marshalReportSourceRequirements(ctx, capture)
		if err != nil {
			t.Fatal("role-only report could not seal complete source requirements", err)
		}
		stored, err := parseReportSourceRequirements(ctx, raw)
		if err != nil || f.server.revalidateReportFlowCapture(ctx, actors[tenant], stored) != nil {
			t.Fatal("current role report source requirements were not readable", err)
		}
		captures[tenant] = stored
	}
	red, blue := f.tenants[0], f.tenants[1]
	f.in(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny-report-role-source", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"context_id": f.contextID}, Priority: 100})
		return err
	})
	ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(red)), actors[red])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[red], captures[red]); err == nil {
		t.Fatal("report reader reused role source after its context denial")
	}
	ctx = auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(blue)), actors[blue])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[blue], captures[blue]); err != nil {
		t.Fatal("role report context denial crossed tenant", err)
	}
	t.Log("real-integration: current app-role Postgres users/policies/canonical role contexts/stored requirements; native flow rows and sender metadata modeled; complete artifact/browser proof remains separate")
}
