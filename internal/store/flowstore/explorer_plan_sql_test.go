// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestExplorerPlanTotalSeriesWireDistinguishesLegacyUnknownFromKnownEmpty(t *testing.T) {
	legacy, err := json.Marshal(PlanResult{})
	if err != nil || strings.Contains(string(legacy), `"total_series"`) {
		t.Fatal("legacy nil stream must remain unavailable, not a false empty/zero stream")
	}
	current, err := json.Marshal(PlanResult{TotalSeries: []PlanPoint{}})
	if err != nil || !strings.Contains(string(current), `"total_series":[]`) {
		t.Fatal("known empty stream lost its explicit empty array")
	}
}

func TestExplorerPlanSQLKeepsScopeOutsideExclusionsAndValuesBound(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	literal := "source' OR tenant_id!='' --"
	plan := flow.QueryPlan{From: now.AddDate(-3, 0, 0), To: now, GroupBy: []string{"src_prefix", "in_if_name"}, Filter: &flow.QueryFilterGroup{Mode: "exclude", Match: "any", Conditions: []flow.QueryPredicate{{Field: "src_as_name", Op: flow.QueryContains, Values: []string{literal}}}}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	sql, params, err := planSQL(plan, "tenant_own.probectl_flows", map[string]map[uint32]string{"192.0.2.1": {1: literal}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, literal) {
		t.Fatal("literal was interpolated into SQL")
	}
	if !strings.Contains(sql, "WHERE tenant_id={tenant:String} AND ts>=") || !strings.Contains(sql, " AND (NOT (") {
		t.Fatal("tenant predicate was not outside excluded expression")
	}
	if len(params) == 0 || !strings.Contains(params["interfaces"], literal) {
		t.Fatal("metadata was lost instead of bound")
	}
	if !strings.Contains(sql, "filtered.g NOT IN (SELECT g FROM ranked") {
		t.Fatal("Other membership did not use the original input key")
	}
	for _, guard := range []string{"max_execution_time=5", "max_memory_usage=536870912", "max_bytes_to_read=268435456", "read_overflow_mode='throw'", "result_overflow_mode='throw'"} {
		if !strings.Contains(sql, guard) {
			t.Errorf("missing execution-cost guard: %s", guard)
		}
	}
	if _, _, err := planSQL(plan, "probectl_flows; SELECT * FROM another_tenant", nil); err == nil {
		t.Fatal("unchecked table identifier accepted")
	}
	plan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: "not-resolved"}}}
	if _, _, err := planSQL(plan, "probectl_flows", nil); err == nil {
		t.Fatal("unresolved saved reference accepted")
	}
}

func TestExplorerPlanTotalPointDecoderAndSQLBoundary(t *testing.T) {
	from := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: from, To: from.Add(150 * time.Second), View: "line", GroupBy: []string{"src_addr"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}, from)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]any{"kind": "counts", "g": []any{}, "c": []any{}, "o": "0", "p": "0", "metrics": []any{"0"}, "total_groups": "1", "oldest_input": from.Format("2006-01-02 15:04:05")}
	point := map[string]any{"kind": "total_point", "g": []any{}, "c": []any{}, "o": "0", "p": "0", "bi": "2", "duration": "30000000000", "metrics": []any{"18446744073709551617"}}
	got, err := decodePlanRows(plan, []map[string]any{counts, point})
	if err != nil || len(got.TotalSeries) != 1 || len(got.TotalSeries[0].Group) != 0 || got.TotalSeries[0].Metrics["bytes:total"] != "18446744073709551617" || got.TotalSeries[0].DurationSeconds != "30.000000000" {
		t.Fatalf("valid independent total point: %+v %v", got.TotalSeries, err)
	}
	// UseNumber is the actual chclient.Decode contract, not the convenient
	// quoted strings in the other decoder fixtures.
	numeric := maps.Clone(point)
	numeric["o"], numeric["p"] = json.Number("0"), json.Number("0")
	if _, err := decodePlanRows(plan, []map[string]any{counts, numeric}); err != nil {
		t.Fatalf("actual JSON UInt8 flag rejected: %v", err)
	}
	for _, change := range []map[string]any{{"g": []any{"192.0.2.1"}}, {"c": []any{"192.0.2.2"}}, {"o": "1"}, {"o": "bad"}, {"o": nil}, {"p": json.Number("0.5")}, {"p": "2"}, {"bi": "-1"}, {"bi": "3"}, {"duration": "1"}} {
		bad := maps.Clone(point)
		maps.Copy(bad, change)
		if _, err := decodePlanRows(plan, []map[string]any{counts, bad}); err == nil {
			t.Errorf("invalid total point accepted: %+v", change)
		}
	}
	if _, err := decodePlanRows(plan, []map[string]any{counts, point, point}); err == nil {
		t.Fatal("duplicate total bucket accepted")
	}
	empty := maps.Clone(counts)
	empty["total_groups"] = "0"
	empty["oldest_input"] = ""
	if _, err := decodePlanRows(plan, []map[string]any{empty, point}); err == nil {
		t.Fatal("total point accepted without contributing input")
	}
	for _, view := range []string{"line", "matrix", "table"} {
		plan.View = view
		if view == "matrix" {
			plan.MatrixWith = []string{"dst_addr"}
		} else {
			plan.MatrixWith = nil
		}
		sql, _, err := planSQL(plan, "probectl_flows", nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(sql, "'total_point'") != (view != "table") {
			t.Fatalf("total output does not match %s view", view)
		}
		if view == "table" {
			if _, err := decodePlanRows(plan, []map[string]any{counts, point}); err == nil {
				t.Fatal("table accepted total bucket stream")
			}
		}
	}
}

func TestExplorerPlanDecoderRefusesBadMetricWidthAndBucketBounds(t *testing.T) {
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []map[string]any{
		{"kind": "detail", "metrics": []any{}, "g": []any{}},
		{"kind": "detail", "metrics": []any{"not-a-number"}, "g": []any{}},
		{"kind": "detail", "metrics": []any{"1"}, "g": []any{"extra"}},
		{"kind": "point", "metrics": []any{"1"}, "g": []any{}, "bi": "-1", "duration": "60000000000"},
		{"kind": "point", "metrics": []any{"1"}, "g": []any{}, "bi": "999999999", "duration": "60000000000"},
		{"kind": "point", "metrics": []any{"1"}, "g": []any{}, "bi": "0", "duration": "1"},
		{"kind": "unregistered", "metrics": []any{"1"}, "g": []any{}},
	} {
		if _, err := decodePlanRows(plan, []map[string]any{row}); err == nil {
			t.Errorf("invalid response accepted: %+v", row)
		}
	}
}

func TestExplorerPlanRankingDepthsAreServerBound(t *testing.T) {
	from := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, view := range []string{"table", "line", "matrix"} {
		t.Run(view, func(t *testing.T) {
			plan := flow.QueryPlan{From: from, To: from.Add(time.Hour), GroupBy: []string{"src_addr"}, View: view, RowLimit: 137, PageSize: 100, SeriesDepth: 17, MatrixDepth: 13}
			if view == "matrix" {
				plan.MatrixWith = []string{"dst_addr"}
			}
			first, bound, err := planSQL(plan, "probectl_flows", nil)
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{"detail_limit": "137", "series_limit": "17", "matrix_depth": "13"} {
				if bound[key] != want {
					t.Fatalf("%s was not server-bound: got %q,want %q", key, bound[key], want)
				}
			}
			if !strings.Contains(first, "rk<={detail_limit:UInt64}") {
				t.Fatal("detail ranking lost typed parameter")
			}
			if view == "line" && !strings.Contains(first, "rk<={series_limit:UInt64}") {
				t.Fatal("chart ranking lost typed parameter")
			}
			if view == "matrix" && !strings.Contains(first, "rk<={matrix_depth:UInt64}") {
				t.Fatal("matrix ranking lost typed parameter")
			}
			plan.RowLimit, plan.SeriesDepth, plan.MatrixDepth = 199, 29, 11
			second, changed, err := planSQL(plan, "probectl_flows", nil)
			if err != nil {
				t.Fatal(err)
			}
			if second != first {
				t.Fatal("changing public ranking depths changed SQL structure")
			}
			if changed["detail_limit"] != "199" || changed["series_limit"] != "29" || changed["matrix_depth"] != "11" {
				t.Fatal("ranking parameter values did not follow the normalized plan")
			}
		})
	}
}
