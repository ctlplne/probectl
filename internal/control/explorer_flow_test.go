// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Keep the read-only UI preview's grammar on the same server-owned registry.
// Regenerate with PROBECTL_UPDATE_FLOW_EXPLORER_WEB_FIXTURE=1 go test
// ./internal/control -run '^TestExplorerFlowWebFixtureMatchesRegistry$'.
func TestExplorerFlowWebFixtureMatchesRegistry(t *testing.T) {
	const path = "../../web/src/test/flowExplorerSchema.json"
	wantJSON, err := json.MarshalIndent(flowExplorerSchema(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PROBECTL_UPDATE_FLOW_EXPLORER_WEB_FIXTURE") == "1" {
		if err := os.WriteFile(path, append(wantJSON, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actual, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("UI preview flow grammar drifted; regenerate from flowExplorerSchema as documented above")
	}
}

func TestExplorerFlowRecordsUseStoredFieldsAndExactAggregates(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	store := flowstore.NewMemory()
	if err := store.Insert(t.Context(), []flowstore.Row{
		{TenantID: red, TS: at, Exporter: "same-router", SrcAddr: "192.0.2.1", DstAddr: "203.0.113.1", DstPort: 443, BytesScaled: 9007199254740993, PacketsScaled: 3},
		{TenantID: blue, TS: at, Exporter: "same-router", SrcAddr: "SECRET-OTHER-TENANT", DstAddr: "203.0.113.1", DstPort: 443, BytesScaled: 999, PacketsScaled: 1},
	}); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(flowstore.WithTenantWriteFence(store, nil))
	query := ai.ExplorerQuery{Question: "Traffic by address and port", Source: ai.ExplorerFlow, From: at.Add(-time.Minute), To: at.Add(time.Minute), Dimensions: []string{"src_addr", "dst_port"}, Groupings: []string{"src_addr", "dst_port"}, Measures: []string{"bytes", "packets", "flows", "bps", "pps", "unique_src", "unique_dst"}, Limit: 100, Visualization: "line", Flow: &flow.QueryPlan{SeriesDepth: 5}}
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("query=%d %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"192.0.2.1", "9007199254740993", "bytes:total_str", "unique_src", "\"flow\""} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("query missing %s: %s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "SECRET-OTHER-TENANT") || strings.Contains(rec.Body.String(), red) || strings.Contains(rec.Body.String(), blue) {
		t.Fatalf("query exposed tenant scope or foreign telemetry: %s", rec.Body.String())
	}
	var result explorerResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Truncated || result.Execution.Truncated {
		t.Fatal("record flow query silently truncated")
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body))
	request.Header.Set("X-Probectl-Tenant", blue)
	foreign := doReq(srv, request)
	if foreign.Code != http.StatusOK || !strings.Contains(foreign.Body.String(), "SECRET-OTHER-TENANT") || strings.Contains(foreign.Body.String(), "192.0.2.1") {
		t.Fatalf("paired tenant query wrong: %d %s", foreign.Code, foreign.Body.String())
	}
}

func TestExplorerFlowComparisonAlignsExactOtherPopulation(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-000000000001"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	store := flowstore.NewMemory()
	rows := []flowstore.Row{
		{TenantID: tenant, TS: at, Protocol: "A", BytesScaled: 9007199254740993},
		{TenantID: tenant, TS: at, Protocol: "B", BytesScaled: 2},
		{TenantID: tenant, TS: at, Protocol: "C", BytesScaled: 5},
		{TenantID: tenant, TS: at.Add(-2 * time.Hour), Protocol: "A", BytesScaled: 9007199254740992},
		{TenantID: tenant, TS: at.Add(-2 * time.Hour), Protocol: "B", BytesScaled: 9007199254740994},
		{TenantID: tenant, TS: at.Add(-2 * time.Hour), Protocol: "C", BytesScaled: 7},
		{TenantID: "00000000-0000-0000-0000-000000000002", TS: at, Protocol: "SECRET", BytesScaled: 999999999},
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(store)
	request := explorerComparisonRequest{Query: ai.ExplorerQuery{Question: "Traffic by protocol", Source: ai.ExplorerFlow, From: at.Add(-time.Minute), To: at.Add(time.Minute), Dimensions: []string{"protocol"}, Groupings: []string{"protocol"}, Measures: []string{"bytes"}, Limit: 2, Flow: &flow.QueryPlan{RowLimit: 2, PageSize: 2}}, PreviousFrom: at.Add(-2*time.Hour - time.Minute), PreviousTo: at.Add(-2*time.Hour + time.Minute)}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("comparison=%d %s", rec.Code, rec.Body.String())
	}
	var result explorerComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Flow == nil || result.Flow.Membership != "shared_top_groups_ranked_by_larger_period_value" || len(result.Rows) != 3 {
		t.Fatalf("unaligned population: %s", rec.Body.String())
	}
	checked := map[string]bool{}
	for _, row := range result.Rows {
		if row.Other {
			if row.DeltaExact == nil || *row.DeltaExact != "-2" {
				t.Fatalf("Other contains different members across periods: %+v", row)
			}
			checked["other"] = true
		}
		if row.Group["protocol"] == "A" {
			if row.DeltaExact == nil || *row.DeltaExact != "1" || row.CurrentExact == nil || *row.CurrentExact != "9007199254740993" {
				t.Fatalf("delta rounded through float: %+v", row)
			}
			checked["A"] = true
		}
	}
	if !checked["other"] || !checked["A"] || strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatalf("comparison omitted expected groups or leaked: %s", rec.Body.String())
	}
}

func TestExplorerFlowJoinedNamesRequireMetricRead(t *testing.T) {
	srv := testServer(fakePinger{})
	query := ai.ExplorerQuery{Question: "Traffic by interface name", Source: ai.ExplorerFlow, Dimensions: []string{"in_if_name"}, Groupings: []string{"in_if_name"}, Measures: []string{"bytes"}, Limit: 100}
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body))
	request = request.WithContext(auth.WithPrincipal(request.Context(), &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}}))
	rec := httptest.NewRecorder()
	apiHandler(srv.handleExplorerQuery).ServeHTTP(rec, request)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "metrics.read") {
		t.Fatalf("joined metadata bypassed source permission: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExplorerFlowComparisonPagesGroupsRatherThanMetricCells(t *testing.T) {
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{GroupBy: []string{"protocol"}, RowLimit: 2, PageSize: 2, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "total", Role: "secondary"}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := []flowstore.PlanRow{{Group: map[string]string{"protocol": "A"}, Metrics: map[string]string{"bytes:total": "9007199254740993", "packets:total": "2"}}, {Group: map[string]string{"protocol": "B"}, Metrics: map[string]string{"bytes:total": "2", "packets:total": "3"}}}
	before := []flowstore.PlanRow{{Group: map[string]string{"protocol": "A"}, Metrics: map[string]string{"bytes:total": "9007199254740992", "packets:total": "1"}}}
	packed, err := packFlowComparisonRows(now, before, plan)
	if err != nil || len(packed) != 2 {
		t.Fatalf("groups incorrectly reduced by metric count: %d %v", len(packed), err)
	}
	aligned, err := alignExactFlowComparison(now, before, plan.GroupBy, []string{"bytes:total", "packets:total"}, 2)
	if err != nil || len(aligned) != 4 {
		t.Fatalf("metric expansion reduced group reach: %d %v", len(aligned), err)
	}
	missing := 0
	for _, row := range aligned {
		if row.DeltaState == "missing_previous" {
			missing++
		}
		if row.Group["protocol"] == "A" && (row.DeltaExact == nil || *row.DeltaExact != "1") {
			t.Fatal("exact delta rounded")
		}
	}
	if missing != 2 {
		t.Fatal("missing period was fabricated as zero")
	}
}

func TestExplorerFlowComparisonMatrixUsesCommonConditionedAxes(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	memory := flowstore.NewMemory()
	rows := []flowstore.Row{
		{TenantID: red, TS: at, SrcAddr: "192.0.2.1", DstAddr: "198.51.100.1", BytesScaled: 100},
		{TenantID: red, TS: at, SrcAddr: "192.0.2.2", DstAddr: "198.51.100.2", BytesScaled: 90},
		{TenantID: red, TS: at.Add(-2 * time.Hour), SrcAddr: "192.0.2.1", DstAddr: "198.51.100.3", BytesScaled: 80},
		{TenantID: red, TS: at.Add(-2 * time.Hour), SrcAddr: "192.0.2.2", DstAddr: "198.51.100.4", BytesScaled: 120},
		{TenantID: blue, TS: at, SrcAddr: "192.0.2.99", DstAddr: "198.51.100.99", BytesScaled: 999999},
	}
	if err := memory.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(memory)
	query := ai.ExplorerQuery{Question: "Compare matrix", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"src_addr"}, MatrixWith: []string{"dst_addr"}, MatrixDepth: 1, View: "matrix", RowLimit: 2, PageSize: 2, BucketSeconds: 60, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}, {Measure: "bytes", Calculation: "p99", Role: "secondary"}}}}
	body, _ := json.Marshal(explorerComparisonRequest{Query: query, PreviousFrom: at.Add(-2*time.Hour - time.Minute), PreviousTo: at.Add(-2*time.Hour + time.Minute)})
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("matrix comparison %d %s", rec.Code, rec.Body.String())
	}
	var result explorerComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, period := range []flowstore.PlanResult{result.Flow.Current, result.Flow.Previous} {
		for _, cell := range period.Matrix {
			if !cell.RowOther && cell.Row["src_addr"] != "192.0.2.2" {
				t.Fatal("period changed common row population")
			}
			if !cell.ColumnOther && cell.Column["dst_addr"] != "198.51.100.4" {
				t.Fatal("period changed common column population")
			}
		}
	}
	if strings.Contains(rec.Body.String(), "192.0.2.99") {
		t.Fatal("matrix leaked sibling")
	}
}

func TestExplorerFlowComparisonChartSelectionIndependentOfDetailLimit(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	memory := flowstore.NewMemory()
	rows := []flowstore.Row{}
	for i := 0; i < 10; i++ {
		for _, stamp := range []time.Time{at, at.Add(-2 * time.Hour)} {
			rows = append(rows, flowstore.Row{TenantID: red, TS: stamp, Protocol: fmt.Sprintf("proto%d", i), BytesScaled: uint64(i + 1)})
		}
	}
	if err := memory.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(memory)
	query := ai.ExplorerQuery{Question: "Separate chart and detail membership", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "line", GroupBy: []string{"protocol"}, RowLimit: 1, PageSize: 1, SeriesDepth: 4, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
	body, _ := json.Marshal(explorerComparisonRequest{Query: query, PreviousFrom: at.Add(-2*time.Hour - time.Minute), PreviousTo: at.Add(-2*time.Hour + time.Minute)})
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("comparison%d %s", rec.Code, rec.Body.String())
	}
	var result explorerComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, period := range []flowstore.PlanResult{result.Flow.Current, result.Flow.Previous} {
		groups := map[string]bool{}
		for _, point := range period.Series {
			groups[point.Group["protocol"]] = true
		}
		if len(period.Rows) != 1 || len(groups) != 4 {
			t.Fatalf("detail limit reduced chart reach: rows%d chart groups%d; want1 and4", len(period.Rows), len(groups))
		}
	}
}

func TestExplorerFlowComparisonMatrixSelectionIndependentOfDetailLimit(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	memory := flowstore.NewMemory()
	rows := []flowstore.Row{}
	for i := 0; i < 10; i++ {
		for _, stamp := range []time.Time{at, at.Add(-2 * time.Hour)} {
			rows = append(rows, flowstore.Row{TenantID: red, TS: stamp, Protocol: fmt.Sprintf("proto%d", i), BytesScaled: uint64(i + 1)})
		}
	}
	if err := memory.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(memory)
	query := ai.ExplorerQuery{Question: "Separate chart and detail membership", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "matrix", MatrixWith: []string{"dst_port"}, MatrixDepth: 4, GroupBy: []string{"protocol"}, RowLimit: 1, PageSize: 1, SeriesDepth: 4, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
	body, _ := json.Marshal(explorerComparisonRequest{Query: query, PreviousFrom: at.Add(-2*time.Hour - time.Minute), PreviousTo: at.Add(-2*time.Hour + time.Minute)})
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("comparison%d %s", rec.Code, rec.Body.String())
	}
	var result explorerComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, period := range []flowstore.PlanResult{result.Flow.Current, result.Flow.Previous} {
		groups := map[string]bool{}
		for _, cell := range period.Matrix {
			if !cell.RowOther {
				groups[cell.Row["protocol"]] = true
			}
		}
		if len(period.Rows) != 1 || len(groups) != 4 {
			t.Fatalf("detail limit reduced chart reach: rows%d chart groups%d; want1 and4", len(period.Rows), len(groups))
		}
	}
}
