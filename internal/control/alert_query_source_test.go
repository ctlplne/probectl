// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSavedQueryAlertTypedGroupsKeepMatrixOtherAndExactMetrics(t *testing.T) {
	condition := alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "18446744073709551616"}
	result := flowstore.PlanResult{Query: flow.QueryPlan{View: "matrix"}, Matrix: []flowstore.PlanMatrixCell{
		{Row: map[string]string{"src_asn": "64512"}, Column: map[string]string{"src_asn": "64513"}, Metrics: map[string]string{"bytes:total": "18446744073709551617"}},
		{RowOther: true, ColumnOther: true, Metrics: map[string]string{"bytes:total": "18446744073709551618"}},
	}}
	groups, err := alertResultGroups(t.Context(), condition, result, 1<<20)
	if err != nil || len(groups) != 2 || groups[0].Dimensions["row.src_asn"] != "64512" || groups[0].Dimensions["column.src_asn"] != "64513" || groups[0].Value != "18446744073709551617" || groups[1].Dimensions["@row_other"] != "true" || groups[1].Dimensions["@column_other"] != "true" {
		t.Fatal("matrix source collapsed axes, omitted Other or rounded its metric", groups, err)
	}
	novel, err := alertResultGroups(t.Context(), alert.QueryCondition{Mode: "new_group"}, result, 1<<20)
	if err != nil || len(novel) != 1 {
		t.Fatal("a summary Other bucket became a new source identity", novel, err)
	}
	result.Query.View = "table"
	result.Rows = []flowstore.PlanRow{{Group: map[string]string{"src_asn": "64512"}, Metrics: map[string]string{"bytes:total": "18446744073709551617"}}}
	result.Other = &flowstore.PlanRow{Other: true, Metrics: map[string]string{"bytes:total": "2"}}
	groups, err = alertResultGroups(t.Context(), condition, result, 1<<20)
	if err != nil || len(groups) != 2 || groups[1].Dimensions["@other"] != "true" {
		t.Fatal("complete table source lost its summary condition", groups, err)
	}
	if groups, err := alertResultGroups(t.Context(), condition, result, 1); err == nil || groups != nil {
		t.Fatal("unadmitted source returned a successful group prefix", groups, err)
	}
}

func TestSavedQueryAlertSnapshotRefusesForeignOrIncompleteTypedSources(t *testing.T) {
	tenant, view := "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333"
	source := alert.QuerySource{ViewID: view, ViewVersion: "1", Condition: alert.QueryCondition{Mode: "new_group"}}
	for _, scenario := range []string{"foreign", "revision", "partial", "missing"} {
		capture := &reportFlowCapture{TenantID: tenant, ObservedAt: time.Now().UTC(), Results: []capturedReportFlow{{TenantID: tenant, ID: view, Version: "1", Period: "current", Result: flowstore.PlanResult{Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}}}}}
		switch scenario {
		case "foreign":
			capture.Results[0].TenantID = "44444444-4444-4444-8444-444444444444"
		case "revision":
			capture.Results[0].Version = "2"
		case "partial":
			capture.Results[0].Result.Coverage.CompleteInputs = false
		case "missing":
			capture.Results = nil
		}
		if snapshot, err := alertQuerySnapshot(t.Context(), tenant, source, capture, 1<<20); err == nil || !reflect.DeepEqual(snapshot, alert.QueryGroupSnapshot{}) {
			t.Fatal("foreign/revised/incomplete source became a complete query selection", scenario, snapshot, err)
		}
	}
}

func TestSavedQueryAlertSignalUsesFlowPlaneAndOpaqueGroupTarget(t *testing.T) {
	group := strings.Repeat("a", 64)
	a := alert.Alert{TenantID: "tenant", RuleID: "rule", Metric: alert.QueryMetric, Labels: map[string]string{"query_group": group, "query_view_id": "view", "server_address": "private source address"}, State: alert.StateFiring, Value: 1, At: time.Now().UTC()}
	fired := signalFromAlert(a)
	a.State, a.Value = alert.StateResolved, 0
	cleared := signalFromAlert(a)
	if fired.Plane != "flow" || fired.Target != "query:rule:"+group || fired.Target != cleared.Target || fired.TenantID != a.TenantID || fired.Attributes["query_group"] != group || fired.Attributes["query_view_id"] != "view" || len(fired.Attributes) != 5 {
		t.Fatal("query predicate lost its normal incident identity", fired, cleared)
	}
	for _, value := range fired.Attributes {
		if strings.Contains(value, "private source address") {
			t.Fatal("generic incident metadata exposed a private source value")
		}
	}
}

func TestSavedQueryAlertRequestKeepsExactConditionAndRejectsMixedSources(t *testing.T) {
	input := alert.QuerySourceInput{ViewID: "11111111-1111-4111-8111-111111111111", ViewVersion: "1", Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "18446744073709551617"}}
	request := alertRequest{Name: "Wide exact condition", QuerySource: &input}
	rule, err := request.toRule()
	if err != nil || rule.Metric != alert.QueryMetric || rule.Threshold != 1 || request.QuerySource.Condition.Threshold != "18446744073709551617" {
		t.Fatal("query request rounded or mixed its condition", rule, err)
	}
	for _, mutate := range []func(*alertRequest){func(r *alertRequest) { r.Metric = "raw_metric" }, func(r *alertRequest) { r.Type = "threshold" }, func(r *alertRequest) { r.Match = map[string]string{"site": "other"} }, func(r *alertRequest) { r.Window = 20 }} {
		changed := request
		mutate(&changed)
		if _, err := changed.toRule(); err == nil {
			t.Fatal("query source accepted conflicting metric/baseline criteria")
		}
	}
}

func TestSavedQueryCurrentGroupInspectionKeepsExactFactsAndExplicitAbsence(t *testing.T) {
	tenant, ruleID, view := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	at := time.Now().UTC()
	source := store.AlertQuerySource{Source: alert.QuerySource{ViewID: view, ViewVersion: "1", Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "18446744073709551616"}}}
	rule := alert.Rule{ID: ruleID, TenantID: tenant, Metric: alert.QueryMetric}
	capture := &reportFlowCapture{TenantID: tenant, ObservedAt: at, Inputs: []reportFlowInput{{ID: view, Version: "1", Period: "current", From: at.Add(-time.Minute), To: at}}, Results: []capturedReportFlow{{TenantID: tenant, ID: view, Version: "1", Period: "current", Result: flowstore.PlanResult{Query: flow.QueryPlan{View: "table", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total"}}}, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, Rows: []flowstore.PlanRow{{Group: map[string]string{"src_addr": "🌐;=source"}, Metrics: map[string]string{"bytes:total": "18446744073709551617"}}}}}}}
	snapshot, err := alertQuerySnapshot(ctx, tenant, source.Source, capture, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	decisions, _, err := alert.EvaluateQueryGroups(ctx, source.Source.Binding(tenant, ruleID), snapshot, source.State, alert.QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	out, err := inspectAlertQueryGroup(ctx, rule, source, capture, decisions[0].Key, 1<<20)
	if err != nil || out.Kind != "current_query_group" || !out.Present || !out.ConditionMet || out.ExactValue != "18446744073709551617" || out.Dimensions["src_addr"] != "🌐;=source" || !out.At.Equal(at) {
		t.Fatal("current inspection lost exact source facts", out, err)
	}
	out.Dimensions["src_addr"] = "changed"
	if capture.Results[0].Result.Rows[0].Group["src_addr"] != "🌐;=source" || source.State.Initialized {
		t.Fatal("manual inspection mutated source or baseline")
	}
	absent, err := inspectAlertQueryGroup(ctx, rule, source, capture, strings.Repeat("f", 64), 1<<20)
	if err != nil || absent.Present || absent.ConditionMet || absent.ExactValue != "" || len(absent.Dimensions) != 0 {
		t.Fatal("absent current group exposed another group's facts", absent, err)
	}
}

func TestSavedQueryInvalidMetricReturnsValidationWithoutPartialSnapshot(t *testing.T) {
	tenant, view := "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333"
	source := alert.QuerySource{ViewID: view, ViewVersion: "1", Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:missing", Comparison: alert.GT, Threshold: "1"}}
	capture := &reportFlowCapture{TenantID: tenant, ObservedAt: time.Now().UTC(), Results: []capturedReportFlow{{TenantID: tenant, ID: view, Version: "1", Period: "current", Result: flowstore.PlanResult{Query: flow.QueryPlan{Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total"}}}, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}}}}}
	snapshot, err := alertQuerySnapshot(t.Context(), tenant, source, capture, 1<<20)
	var domain *apierror.Error
	if !errors.As(err, &domain) || domain.Kind != apierror.KindValidation || !reflect.DeepEqual(snapshot, alert.QueryGroupSnapshot{}) {
		t.Fatal("invalid source metric was an internal error or a partial success", snapshot, err)
	}
}
