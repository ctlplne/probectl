// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDependencyWorkflowNativeUsesCurrentTenantEvidence(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	seedInterfaceRoleMCPConsent(d.f)
	modern := interfaceRoleNativeTLSCaller(t, d.f, "2026-07-28")
	legacy := interfaceRoleNativeTLSCaller(t, d.f, "2025-11-25")
	for _, tenant := range d.f.tenants {
		var series []tsdb.Series
		for _, node := range d.graphs[tenant].Nodes {
			series = append(series, tsdb.Series{Metric: d.rules[tenant].Metric, Labels: map[string]string{"test_id": node.TestID, "agent_id": node.AgentID}, Value: 0})
		}
		eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: series}, alert.ChannelDeps{Mail: &dependencyRoutingMail{}}, time.Second, tenancy.ID(tenant), nil, d.f.server.log,
			AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
		if !ok {
			t.Fatal("shipping evaluator unavailable")
		}
		d.f.server.WithAlertState(tenant, eval.Engine())
		if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
			t.Fatal(err)
		}
		var child alert.ActiveAlert
		for _, active := range eval.Engine().Active() {
			if active.Labels["test_id"] == d.graphs[tenant].Nodes[1].TestID {
				child = active
			}
		}
		if child.Fingerprint == "" {
			t.Fatal("held child disappeared from current evaluation")
		}
		for _, call := range []func(string, string, any, any, bool){modern, legacy} {
			var out alert.DependencyWorkflow
			call(tenant, "alert_dependency_workflow", map[string]any{"fingerprint": child.Fingerprint}, &out, true)
			if out.State != "held" || out.ContextID != d.f.contextID || out.EntityID != d.graphs[tenant].Nodes[1].EntityID || out.EvidenceID == "" || out.ObservationID == "" || len(out.Causes) != 1 || out.Causes[0].IncidentID != d.cases[tenant] {
				t.Fatal("native workflow lost its exact tenant source and canonical cause", out)
			}
			call(dependencyOtherTenant(d.f.tenants, tenant), "alert_dependency_workflow", map[string]any{"fingerprint": child.Fingerprint}, nil, false)
		}
	}
	t.Log("real-integration: both authenticated HTTPS native wire versions and paired PG/RLS tenants; source observations and delivery sink modeled")
}
