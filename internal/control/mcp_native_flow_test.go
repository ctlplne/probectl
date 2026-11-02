// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

// nativeFlowViewSaveDefinition reconstructs the save input after a client edits the
// declared view. The save path revalidates every pinned ID for the tenant.
func nativeFlowViewSaveDefinition(view mcp.NativeFlowViewDefinition) flow.QueryViewDefinition {
	ids := make(map[string]string, len(view.TagIDs))
	for _, tag := range view.TagIDs {
		ids[tag.Field] = tag.ID
	}
	return flow.QueryViewDefinition{Name: view.Name, Description: view.Description,
		Labels: view.Labels, Visibility: view.Visibility, Plan: view.Plan, Time: view.Time,
		Comparison: view.Comparison, AutoRefreshSeconds: view.AutoRefreshSeconds,
		Display: view.Display, TagIDs: ids}
}

func TestNativeFlowViewProjectsPinnedTagIdentities(t *testing.T) {
	source := flow.SavedQueryView{Definition: flow.QueryViewDefinition{TagIDs: map[string]string{
		"tag.region": "region-id", "tag.customer": "customer-id",
	}}}
	projected := projectNativeFlowView(source)
	want := []mcp.NativeFlowTagID{{Field: "tag.customer", ID: "customer-id"}, {Field: "tag.region", ID: "region-id"}}
	if !reflect.DeepEqual(projected.Definition.TagIDs, want) {
		t.Fatalf("native tag identities = %+v, want %+v", projected.Definition.TagIDs, want)
	}
	if got := nativeFlowViewSaveDefinition(projected.Definition).TagIDs; !reflect.DeepEqual(got, source.Definition.TagIDs) {
		t.Fatalf("native round trip changed pinned tag identities: %+v", got)
	}
}

func TestNativeMCPAndRESTSchemaReportConfiguredQueryBudgets(t *testing.T) {
	core := testServer(fakePinger{})
	core.flowRenderBudget = configuredNativeFlowRenderBudget(&config.Config{FlowMCPSourceBytes: 64 << 20, FlowMCPWireBytes: 256 << 20, FlowMCPResultNodes: 8 << 20, FlowMCPCSVPageBytes: 4 << 20})
	budget := flowstore.DefaultExplorerBudget()
	budget.ExecutionLimit = 1250 * time.Millisecond
	budget.ReadRows, budget.MemoryBytes = 12345678, 1<<30
	if err := flowstore.AttachExplorerBudget(core.flowStore, budget); err != nil {
		t.Fatal(err)
	}
	p := &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", UserID: "owner", Permissions: map[string]bool{"ai.query": true, "flow.read": true}}
	request := httptest.NewRequest(http.MethodGet, "/v1/explorer/schema", nil)
	request = request.WithContext(auth.WithPrincipal(request.Context(), p))
	w := httptest.NewRecorder()
	if err := core.handleExplorerSchema(w, request); err != nil {
		t.Fatal(err)
	}
	var rest struct {
		Flow struct {
			Limits     map[string]any             `json:"limits"`
			RenderCost mcp.NativeFlowRenderBudget `json:"render_cost"`
		} `json:"flow"`
	}
	if json.Unmarshal(w.Body.Bytes(), &rest) != nil || rest.Flow.Limits["execution_seconds"] != 1.25 || rest.Flow.Limits["memory_bytes"] != float64(1<<30) {
		t.Fatal("REST schema reported stale cost constants")
	}
	var reply struct {
		Result struct {
			Data struct {
				Limits     map[string]any             `json:"limits"`
				RenderCost mcp.NativeFlowRenderBudget `json:"render_cost"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	wire := nativeControlMCP(t, core).Handle(t.Context(), p, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flow_explorer_schema","arguments":{}}}`))
	if json.Unmarshal(wire, &reply) != nil || !reflect.DeepEqual(reply.Result.Data.Limits, rest.Flow.Limits) {
		t.Fatal("MCP cost discovery diverged from REST")
	}
	if rest.Flow.RenderCost != core.flowRenderBudget || reply.Result.Data.RenderCost != core.flowRenderBudget {
		t.Fatal("MCP and REST discovery did not report the effective render policy")
	}
}

func TestNativeMCPFlowCatalogUsesSharedServer(t *testing.T) {
	core := testServer(fakePinger{})
	source := AISources{Flow: core.flowStore}
	// Compatibility of this before reproduction: old constructors lack the
	// optional service binding, and must fail on actual missing discovery.
	if field := reflect.ValueOf(&source).Elem().FieldByName("NativeFlow"); field.IsValid() {
		field.Set(reflect.ValueOf(core))
	}
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	server := NewMCPServerWithPolicyLoader(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, pathstore.NewMemory(), 0, gate, nil, nil, func(context.Context, string) ([]auth.Policy, error) { return nil, nil }, source)
	p := &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", UserID: "owner", Permissions: map[string]bool{"ai.query": true, "flow.read": true, "flow.filters.write": true, "flow.views.write": true}}
	var response struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(server.Handle(t.Context(), p, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)), &response); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range response.Result.Tools {
		names[tool.Name] = true
	}
	for _, name := range []string{"flow_explorer_plan", "flow_explorer_schema", "flow_explorer_query", "flow_explorer_compare", "flow_explorer_page", "flow_explorer_comparison_page", "flow_filter_list", "flow_filter_get", "flow_filter_save", "flow_filter_delete", "flow_view_list", "flow_view_get", "flow_view_save", "flow_view_delete", "flow_view_favorite", "flow_view_run"} {
		if !names[name] {
			t.Errorf("native flow operation %s is absent from authenticated MCP discovery", name)
		}
	}
}

func nativeControlMCP(t *testing.T, core *Server) *mcp.Server {
	t.Helper()
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	server := NewMCPServerWithPolicyLoader(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, pathstore.NewMemory(), 0, gate, nil, nil, func(context.Context, string) ([]auth.Policy, error) { return nil, nil }, AISources{Flow: core.flowStore, NativeFlow: core})
	// Simulation only: domain/egress call audits use explicit successful test seams.
	// Real PG/wire admission/audit proofs remain separate required evidence.
	mcp.WithCallAudit(func(context.Context, mcp.CallEvent) error { return nil })(server)
	return server
}

func TestNativeMCPCSVExportIsDiscoverable(t *testing.T) {
	server := nativeControlMCP(t, testServer(fakePinger{}))
	p := &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", UserID: "owner", Permissions: map[string]bool{"ai.query": true, "flow.read": true}}
	raw := server.Handle(t.Context(), p, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if !strings.Contains(string(raw), `"name":"flow_explorer_csv"`) {
		t.Fatal("native MCP cannot export complete frozen CSV records")
	}
}
func nativeControlCall(t *testing.T, server *mcp.Server, p *auth.Principal, name string, args any) (json.RawMessage, bool) {
	t.Helper()
	request, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool            `json:"isError"`
			Data    json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(server.Handle(t.Context(), p, request), &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Result.Data, len(reply.Error) > 0 || reply.Result.IsError
}
func TestNativeMCPProjectionDropsPhysicalFieldsAndPreservesExactValues(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol", "exporter"}, MatrixWith: []string{"dst_port"}, View: "matrix", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}}, at)
	if err != nil {
		t.Fatal(err)
	}
	row := flowstore.PlanRow{Group: map[string]string{"protocol": "ipfix", "exporter": "router", "tenant_id": "PRIVATE_SCOPE_VALUE", "new_store_column": "PRIVATE_UNLISTED_VALUE"}, Metrics: map[string]string{"bytes:total": "9007199254740993", "unique_src:total": "3", "new_store_metric": "PRIVATE_METRIC_VALUE"}}
	point := flowstore.PlanPoint{Group: row.Group, TS: at, DurationSeconds: "60.000000000", Metrics: row.Metrics}
	source := flowstore.PlanResult{Query: plan, Source: "raw", ResolutionSeconds: 60, TotalGroups: 1, Rows: []flowstore.PlanRow{row}, ChartRows: []flowstore.PlanRow{row}, MatrixRows: []flowstore.PlanRow{row}, MatrixColumns: []flowstore.PlanRow{{Group: map[string]string{"dst_port": "443"}, Metrics: row.Metrics}}, Totals: map[string]string{"bytes:total": "9007199254740993", "unique_src:total": "7"}, Series: []flowstore.PlanPoint{point}, TotalSeries: []flowstore.PlanPoint{{TS: at, DurationSeconds: "60", Metrics: map[string]string{"bytes:total": "9007199254740993", "unique_src:total": "7"}}}, SavedFilterVersions: map[string]int64{"filter-own": 9007199254740993}, OldestInput: at.Add(-time.Hour), Coverage: &flowstore.PlanSourceCoverage{Fields: []string{"protocol", "exporter", "tenant_id"}, ResolutionSeconds: 60, CompleteInputs: true}, Matrix: []flowstore.PlanMatrixCell{{Row: row.Group, Column: map[string]string{"dst_port": "443"}, Metrics: row.Metrics}}}
	native, err := projectNativeFlowQuery(explorerResult{Flow: &source, Preview: "PRIVATE_SQL_PREVIEW", EvidencePath: "PRIVATE_CACHE_PATH"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE_", "tenant_id", "new_store_column", "new_store_metric", "oldest_input", "preview", "evidence_path"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("storage/private field crossed native MCP projection", private)
		}
	}
	if native.Flow.Rows[0].Metrics[0].Value != "9007199254740993" || native.Flow.FilterVersions[0].Version != "9007199254740993" || native.Flow.Totals[1].Value != "7" || len(native.Flow.Rows[0].Group) != 2 || !strings.Contains(string(encoded), ".123456789Z") {
		t.Fatal("native projection lost exact values, time or independent cardinality total")
	}
	source.Rows[0].Metrics["bytes:total"] = "not-a-numeric-measure"
	if _, err := projectNativeFlow(source); err == nil {
		t.Fatal("untrusted nonnumeric source measure reached native wire")
	}
}

func TestNativeMCPProjectionRequiresBoundedDecimalNumbers(t *testing.T) {
	metrics := []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}
	for _, value := range []string{"1/2", "0xff", "1e3", "+1", "-1", strings.Repeat("9", 257), "0." + strings.Repeat("1", 19)} {
		if _, err := nativeFlowValues(metrics, map[string]string{"bytes:total": value}, false); err == nil {
			t.Fatalf("noncontract measure %q crossed native projection", value)
		}
	}
	for _, value := range []string{"0", "9007199254740993", "0.123456789012345678"} {
		out, err := nativeFlowValues(metrics, map[string]string{"bytes:total": value}, false)
		if err != nil || out[0].Value != value || !out[0].Defined {
			t.Fatal("exact decimal measure changed", err)
		}
	}
	for _, duration := range []string{"1/2", "0xff", "1e3", "+1", "0"} {
		if _, err := nativeFlowPoints([]flowstore.PlanPoint{{TS: time.Now(), DurationSeconds: duration, Metrics: map[string]string{"bytes:total": "1"}}}, nil, metrics); err == nil {
			t.Fatal("noncontract interval crossed native projection", duration)
		}
	}
	point := flowstore.PlanPoint{TS: time.Date(2026, 10, 20, 0, 0, 0, 123456789, time.UTC), DurationSeconds: "0.000000001", Metrics: map[string]string{"bytes:total": "9007199254740993"}}
	out, err := nativeFlowPoints([]flowstore.PlanPoint{point}, nil, metrics)
	if err != nil || len(out) != 1 || out[0].DurationSeconds != point.DurationSeconds || out[0].TS != point.TS || out[0].Metrics[0].Value != "9007199254740993" {
		t.Fatal("exact nanosecond interval or high counter changed", err)
	}
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: point.TS.Add(-time.Minute), To: point.TS.Add(time.Minute), View: "table", Metrics: metrics}, point.TS)
	if err != nil {
		t.Fatal(err)
	}
	base := flowstore.PlanResult{Query: plan, Source: "raw", ResolutionSeconds: 60}
	group := map[string]string{}
	for _, field := range plan.GroupBy {
		group[field] = "source-value"
	}
	validDelta := "-1"
	validComparison := explorerComparisonResult{Flow: &flowExplorerComparisonData{Current: base, Previous: base}, Rows: []explorerComparisonRow{{Group: group, Measure: "bytes:total", Aggregation: "total", DeltaExact: &validDelta}}}
	validProjected, err := projectNativeFlowComparison(validComparison)
	if err != nil || len(validProjected.Rows) != 1 || *validProjected.Rows[0].Delta != "-1" {
		t.Fatal("valid signed decimal comparison refused", err)
	}
	for _, invalid := range []string{"1/2", "0xff", "1e3", "+1", strings.Repeat("9", 257)} {
		comparison := explorerComparisonResult{Flow: &flowExplorerComparisonData{Current: base, Previous: base}, Rows: []explorerComparisonRow{{Group: group, Measure: "bytes:total", Aggregation: "total", DeltaExact: &invalid}}}
		if _, err := projectNativeFlowComparison(comparison); err == nil {
			t.Fatal("nondecimal comparison delta crossed native projection", invalid)
		}
	}
}

func TestNativeMCPQueriesAndLibrariesUseAuthenticatedTenantAndOwner(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Now().UTC().Add(-10 * time.Minute)
	before := at.Add(-time.Hour)
	data := flowstore.NewMemory()
	if err := data.Insert(t.Context(), []flowstore.Row{{TenantID: red, TS: at, Protocol: "RED_NATIVE_MCP", BytesScaled: 9007199254740993}, {TenantID: blue, TS: at, Protocol: "BLUE_NATIVE_MCP", BytesScaled: 9007199254740994}, {TenantID: red, TS: before, Protocol: "RED_NATIVE_MCP", BytesScaled: 4503599627370497}, {TenantID: blue, TS: before, Protocol: "BLUE_NATIVE_MCP", BytesScaled: 4503599627370498}}); err != nil {
		t.Fatal(err)
	}
	core := testServer(fakePinger{}).WithFlowStore(data)
	server := nativeControlMCP(t, core)
	principal := func(tenant, user string) *auth.Principal {
		return &auth.Principal{TenantID: tenant, UserID: user, Permissions: map[string]bool{"ai.query": true, "flow.read": true, "flow.filters.write": true, "flow.views.write": true}}
	}
	var savedRedFilter, savedRedView string
	cleanups := []struct {
		p                                        *auth.Principal
		view, viewVersion, filter, filterVersion string
	}{}
	for _, lane := range []struct{ tenant, protocol, foreign, current, previous string }{{red, "RED_NATIVE_MCP", "BLUE_NATIVE_MCP", "9007199254740993", "4503599627370497"}, {blue, "BLUE_NATIVE_MCP", "RED_NATIVE_MCP", "9007199254740994", "4503599627370498"}} {
		p := principal(lane.tenant, "alice")
		raw, failed := nativeControlCall(t, server, p, "flow_explorer_schema", struct{}{})
		var schema mcp.NativeFlowSchemaResult
		if failed || json.Unmarshal(raw, &schema) != nil || schema.Limits.MaxTableRows != 50000 || schema.Limits.MaxGroups != 8 || schema.Limits.MaxExpandedConditions != 1000 {
			t.Fatal("native schema narrowed public reach")
		}
		plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		raw, failed = nativeControlCall(t, server, p, "flow_explorer_query", map[string]any{"plan": plan})
		var result mcp.NativeFlowQueryResult
		if failed || json.Unmarshal(raw, &result) != nil || len(result.Flow.Rows) != 1 || result.Flow.Rows[0].Group[0].Value != lane.protocol || result.Flow.Rows[0].Metrics[0].Value != lane.current || strings.Contains(string(raw), lane.foreign) || strings.Contains(string(raw), lane.tenant) {
			t.Fatalf("native MCP query changed isolation or exact data: failed=%v data=%s", failed, raw)
		}
		raw, failed = nativeControlCall(t, server, p, "flow_explorer_compare", mcp.NativeFlowCompareInput{Plan: plan, PreviousFrom: before.Add(-time.Minute), PreviousTo: before.Add(time.Minute)})
		var comparison mcp.NativeFlowComparisonResult
		if failed || json.Unmarshal(raw, &comparison) != nil || len(comparison.Rows) == 0 || comparison.Current.Rows[0].Metrics[0].Value != lane.current || comparison.Previous.Rows[0].Metrics[0].Value != lane.previous {
			t.Fatal("native MCP comparison changed exact periods")
		}
		expression := flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "protocol", Op: flow.QueryEqual, Values: []string{lane.protocol}}}}
		raw, failed = nativeControlCall(t, server, p, "flow_filter_save", mcp.NativeFlowFilterInput{Name: lane.protocol, Expression: expression})
		var filter mcp.NativeFlowFilter
		if failed || json.Unmarshal(raw, &filter) != nil || filter.Version != "1" {
			t.Fatal("native filter creation failed")
		}
		if lane.tenant == red {
			savedRedFilter = filter.ID
		}
		for _, call := range []struct {
			name string
			args any
		}{{"flow_filter_get", map[string]any{"id": filter.ID}}, {"flow_filter_list", map[string]any{}}} {
			if _, failed := nativeControlCall(t, server, p, call.name, call.args); failed {
				t.Fatal("native filter read failed", call.name)
			}
		}
		raw, failed = nativeControlCall(t, server, p, "flow_filter_save", mcp.NativeFlowFilterInput{ID: filter.ID, Version: filter.Version, Name: lane.protocol, Expression: expression})
		if failed || json.Unmarshal(raw, &filter) != nil || filter.Version != "2" {
			t.Fatal("native filter update lost exact revision")
		}
		definition := flow.QueryViewDefinition{Name: lane.protocol, Plan: plan, Display: &flow.QueryViewDisplay{TimeStyle: "horizon", HorizonScale: "lane"}}
		raw, failed = nativeControlCall(t, server, p, "flow_view_save", flow.SaveQueryView{Definition: definition})
		var view mcp.NativeFlowView
		if failed || json.Unmarshal(raw, &view) != nil || view.Version != "1" || view.Definition.Display.HorizonScale != "lane" {
			t.Fatal("native saved view lost complete definition")
		}
		if lane.tenant == red {
			savedRedView = view.ID
		}
		if _, failed := nativeControlCall(t, server, principal(lane.tenant, "bob"), "flow_view_get", map[string]any{"id": view.ID}); !failed {
			t.Fatal("native private view crossed owner")
		}
		view.Definition.Visibility = "tenant"
		raw, failed = nativeControlCall(t, server, p, "flow_view_save", flow.SaveQueryView{ID: view.ID, Version: view.Version, Definition: nativeFlowViewSaveDefinition(view.Definition)})
		if failed || json.Unmarshal(raw, &view) != nil || view.Version != "2" {
			t.Fatal("native saved view update failed")
		}
		bob := principal(lane.tenant, "bob")
		if _, failed := nativeControlCall(t, server, bob, "flow_view_get", map[string]any{"id": view.ID}); failed {
			t.Fatal("native explicit shared read refused")
		}
		if _, failed := nativeControlCall(t, server, bob, "flow_view_delete", map[string]any{"id": view.ID, "version": view.Version}); !failed {
			t.Fatal("native shared reader deleted owner view")
		}
		for _, call := range []struct {
			name string
			args any
		}{{"flow_view_favorite", map[string]any{"id": view.ID, "favorite": true}}, {"flow_view_list", map[string]any{"tab": "favorites"}}, {"flow_view_run", map[string]any{"id": view.ID}}} {
			if _, failed := nativeControlCall(t, server, bob, call.name, call.args); failed {
				t.Fatal("native saved-view operation failed", call.name)
			}
		}
		if lane.tenant == blue {
			for _, call := range []struct {
				name string
				args any
			}{{"flow_filter_get", map[string]any{"id": savedRedFilter}}, {"flow_filter_save", mcp.NativeFlowFilterInput{ID: savedRedFilter, Version: "2", Name: "foreign overwrite", Expression: expression}}, {"flow_filter_delete", map[string]any{"id": savedRedFilter, "version": "2"}}, {"flow_view_get", map[string]any{"id": savedRedView}}, {"flow_view_save", flow.SaveQueryView{ID: savedRedView, Version: "2", Definition: definition}}, {"flow_view_delete", map[string]any{"id": savedRedView, "version": "2"}}, {"flow_view_favorite", map[string]any{"id": savedRedView, "favorite": true}}, {"flow_view_run", map[string]any{"id": savedRedView}}} {
				if _, failed := nativeControlCall(t, server, p, call.name, call.args); !failed {
					t.Fatal("native MCP leaked a foreign resource", call.name)
				}
			}
		}
		cleanups = append(cleanups, struct {
			p                                        *auth.Principal
			view, viewVersion, filter, filterVersion string
		}{p, view.ID, view.Version, filter.ID, filter.Version})
	}
	for _, item := range cleanups {
		if _, failed := nativeControlCall(t, server, item.p, "flow_view_delete", map[string]any{"id": item.view, "version": item.viewVersion}); failed {
			t.Fatal("native owner view deletion failed")
		}
		if _, failed := nativeControlCall(t, server, item.p, "flow_filter_delete", map[string]any{"id": item.filter, "version": item.filterVersion}); failed {
			t.Fatal("native tenant filter deletion failed")
		}
	}
	// Pages require configured shared storage and reject forged/cross-kind cursors.
	for _, name := range []string{"flow_explorer_page", "flow_explorer_comparison_page"} {
		if _, failed := nativeControlCall(t, server, principal(red, "alice"), name, map[string]any{"cursor": "foreign-or-malformed"}); !failed {
			t.Fatal("native page accepted an unavailable/forged continuation")
		}
	}
}
