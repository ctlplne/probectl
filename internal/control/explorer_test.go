// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

func TestExplorerQuerySuggestionsAndExecutionReceiptAreTenantScoped(t *testing.T) {
	flows := flowstore.NewMemory()
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	rows := []flowstore.Row{
		{TenantID: "00000000-0000-0000-0000-000000000001", AgentID: "a", Exporter: "site-a", TS: at, InIf: 7, BytesScaled: 9000, PacketsScaled: 9},
		{TenantID: "00000000-0000-0000-0000-000000000002", AgentID: "b", Exporter: "SECRET-SITE-B", TS: at, InIf: 9, BytesScaled: 999999, PacketsScaled: 999},
	}
	if err := flows.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(flows)
	body := []byte(`{
		"question":"Show top talkers by site","source":"flow",
		"from":"2026-07-14T11:00:00Z","to":"2026-07-14T13:00:00Z",
		"dimensions":["site","interface"],"groupings":["site"],
		"measures":["bps"],"visualization":"bar","limit":100
	}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("query = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "site-a") || strings.Contains(rec.Body.String(), "SECRET-SITE-B") {
		t.Fatalf("tenant-a Explorer response leaked or omitted data: %s", rec.Body.String())
	}
	var got explorerResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suggestions["site"]) != 1 || got.Suggestions["site"][0] != "site-a" {
		t.Fatalf("tenant-a suggestions = %+v", got.Suggestions)
	}
	if got.Execution.ContractVersion != "explorer-execution/v1" ||
		!got.Execution.TenantScoped ||
		got.Execution.Source != ai.ExplorerFlow ||
		got.Execution.Recipe != "custom" ||
		got.Execution.Bounds.RowLimit != 100 ||
		got.Execution.SourceRows != 1 ||
		got.Execution.ReturnedRows != 1 ||
		got.Execution.Truncated ||
		got.Execution.TruncationReason != "none" {
		t.Fatalf("tenant-a execution receipt = %+v", got.Execution)
	}
	if got.Execution.Bounds.From != time.Date(2026, 7, 14, 11, 0, 0, 0, time.UTC) ||
		got.Execution.Bounds.To != time.Date(2026, 7, 14, 13, 0, 0, 0, time.UTC) {
		t.Fatalf("tenant-a receipt bounds = %+v", got.Execution.Bounds)
	}
	if strings.Contains(rec.Body.String(), "00000000-0000-0000-0000-000000000001") ||
		strings.Contains(rec.Body.String(), "00000000-0000-0000-0000-000000000002") {
		t.Fatalf("Explorer response exposed tenant identity: %s", rec.Body.String())
	}

	reqB := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body))
	reqB.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	recB := doReq(srv, reqB)
	if recB.Code != http.StatusOK || !strings.Contains(recB.Body.String(), "SECRET-SITE-B") || strings.Contains(recB.Body.String(), "site-a") {
		t.Fatalf("tenant-b Explorer response = %d %s", recB.Code, recB.Body.String())
	}
	var gotB explorerResult
	if err := json.Unmarshal(recB.Body.Bytes(), &gotB); err != nil {
		t.Fatal(err)
	}
	if gotB.Execution.SourceRows != 1 || gotB.Execution.ReturnedRows != 1 || !gotB.Execution.TenantScoped {
		t.Fatalf("tenant-b execution receipt = %+v", gotB.Execution)
	}
}

func TestExplorerComparisonRowsSuggestionsAndExecutionReceiptsAreTenantScoped(t *testing.T) {
	const (
		tenantA = "00000000-0000-0000-0000-000000000001"
		tenantB = "00000000-0000-0000-0000-000000000002"
	)
	flows := flowstore.NewMemory()
	rows := []flowstore.Row{
		{TenantID: tenantA, AgentID: "a", Exporter: "site-a", TS: time.Date(2026, 7, 14, 12, 30, 0, 0, time.UTC), InIf: 7, BytesScaled: 9000, PacketsScaled: 9},
		{TenantID: tenantA, AgentID: "a", Exporter: "site-a", TS: time.Date(2026, 7, 14, 10, 30, 0, 0, time.UTC), InIf: 7, BytesScaled: 4500, PacketsScaled: 4},
		{TenantID: tenantB, AgentID: "b", Exporter: "SECRET-SITE-B", TS: time.Date(2026, 7, 14, 12, 30, 0, 0, time.UTC), InIf: 9, BytesScaled: 999999, PacketsScaled: 999},
		{TenantID: tenantB, AgentID: "b", Exporter: "SECRET-PREVIOUS-B", TS: time.Date(2026, 7, 14, 10, 30, 0, 0, time.UTC), InIf: 9, BytesScaled: 888888, PacketsScaled: 888},
	}
	if err := flows.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(flows)
	body := []byte(`{
		"query":{
			"question":"Show top talkers by site","source":"flow",
			"from":"2026-07-14T12:00:00Z","to":"2026-07-14T13:00:00Z",
			"dimensions":["site","interface"],"groupings":["site"],
			"measures":["bps"],"visualization":"bar","limit":100
		},
		"previous_from":"2026-07-14T10:00:00Z",
		"previous_to":"2026-07-14T11:00:00Z"
	}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("comparison = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "site-a") ||
		strings.Contains(rec.Body.String(), "SECRET-SITE-B") ||
		strings.Contains(rec.Body.String(), "SECRET-PREVIOUS-B") {
		t.Fatalf("tenant-a Explorer comparison leaked or omitted data: %s", rec.Body.String())
	}
	var got explorerComparisonResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ContractVersion != "explorer-comparison/v1" || got.State != "comparable" || len(got.Rows) != 1 {
		t.Fatalf("comparison metadata = %+v", got)
	}
	if got.Rows[0].Group["site"] != "site-a" || got.Rows[0].Delta == nil || got.Rows[0].PercentChange == nil {
		t.Fatalf("comparison row = %+v", got.Rows[0])
	}
	if values := got.Suggestions["site"]; len(values) != 1 || values[0] != "site-a" {
		t.Fatalf("tenant-a comparison suggestions = %+v", got.Suggestions)
	}
	if got.Execution.ContractVersion != "explorer-comparison-execution/v1" ||
		!got.Execution.TenantScoped ||
		!got.Execution.Current.TenantScoped ||
		!got.Execution.Previous.TenantScoped ||
		got.Execution.Current.SourceRows != 1 ||
		got.Execution.Previous.SourceRows != 1 ||
		got.Execution.Alignment.ReturnedRows != 1 ||
		got.Execution.Alignment.RowLimit != 100 ||
		got.Execution.Alignment.TruncationReason != "none" {
		t.Fatalf("comparison execution receipt = %+v", got.Execution)
	}
	if strings.Contains(rec.Body.String(), tenantA) || strings.Contains(rec.Body.String(), tenantB) {
		t.Fatalf("comparison response exposed tenant identity: %s", rec.Body.String())
	}
}

func TestExplorerExecutionReceiptContainsFilterKeysButNotValues(t *testing.T) {
	flows := flowstore.NewMemory()
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	if err := flows.Insert(t.Context(), []flowstore.Row{{
		TenantID: "00000000-0000-0000-0000-000000000001",
		AgentID:  "a",
		Exporter: "site-a",
		TS:       at,
		InIf:     7,
	}}); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(flows)
	body := []byte(`{
		"template":"top-talkers-site",
		"question":"Show top talkers by site","source":"flow",
		"from":"2026-07-14T11:00:00Z","to":"2026-07-14T13:00:00Z",
		"dimensions":["site"],"filters":{"site":"site-a"},
		"measures":["bps"],"visualization":"table","limit":100
	}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("query = %d %s", rec.Code, rec.Body.String())
	}
	var got explorerResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Execution.Recipe != "top-talkers-site" ||
		len(got.Execution.FilterKeys) != 1 ||
		got.Execution.FilterKeys[0] != "site" {
		t.Fatalf("execution filter receipt = %+v", got.Execution)
	}
	encoded, err := json.Marshal(got.Execution)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"site-a", "00000000-0000-0000-0000-000000000001", "SELECT", "EXPLAIN"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("execution receipt exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestExplorerExecutionReceiptExplainsRowLimitTruncation(t *testing.T) {
	const tenantID = "00000000-0000-0000-0000-000000000001"
	flows := flowstore.NewMemory()
	rows := []flowstore.Row{
		{TenantID: tenantID, AgentID: "a", Exporter: "site-a", TS: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC), InIf: 7, BytesScaled: 9000, PacketsScaled: 9},
		{TenantID: tenantID, AgentID: "a", Exporter: "site-a", TS: time.Date(2026, 7, 14, 12, 1, 0, 0, time.UTC), InIf: 7, BytesScaled: 8000, PacketsScaled: 8},
	}
	if err := flows.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowStore(flows)
	body := []byte(`{
		"question":"Show bounded flow rows","source":"flow",
		"from":"2026-07-14T11:00:00Z","to":"2026-07-14T13:00:00Z",
		"dimensions":["site"],"measures":["bps"],
		"visualization":"table","limit":1
	}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("query = %d %s", rec.Code, rec.Body.String())
	}
	var got explorerResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated ||
		!got.Execution.Truncated ||
		got.Execution.TruncationReason != "row_limit" ||
		got.Execution.SourceRows != 2 ||
		got.Execution.ReturnedRows != 1 {
		t.Fatalf("truncated execution receipt = %+v", got.Execution)
	}
}

func TestAlignExplorerComparisonMakesUndefinedDeltasExplicit(t *testing.T) {
	current := []ai.Row{
		{"site": "zero", "bps": 10.0},
		{"site": "new", "bps": 7.0},
	}
	previous := []ai.Row{
		{"site": "zero", "bps": 0.0},
		{"site": "gone", "bps": 4.0},
	}
	rows, truncated := alignExplorerComparison(current, previous, []string{"site"}, []string{"bps"}, 100)
	if truncated || len(rows) != 3 {
		t.Fatalf("rows = %+v, truncated = %v", rows, truncated)
	}
	states := map[string]string{}
	for _, row := range rows {
		states[row.Group["site"]] = row.DeltaState
		if row.Group["site"] == "zero" && (row.Delta == nil || row.PercentChange != nil) {
			t.Fatalf("zero baseline must keep absolute delta and omit percentage: %+v", row)
		}
	}
	if states["zero"] != "zero_baseline" || states["new"] != "missing_previous" || states["gone"] != "missing_current" {
		t.Fatalf("delta states = %+v", states)
	}
}

func TestExplorerComparisonRejectsCurrentStateOnlySource(t *testing.T) {
	srv := testServer(fakePinger{})
	body := []byte(`{
		"query":{"question":"Show SLOs","source":"slo","measures":["burn_rate"]},
		"previous_from":"2026-07-14T10:00:00Z",
		"previous_to":"2026-07-14T11:00:00Z"
	}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(body)))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "does not retain") {
		t.Fatalf("current-state source = %d %s", rec.Code, rec.Body.String())
	}
}

func TestExplorerTimeVisualizationsDeclareOccurredAtColumn(t *testing.T) {
	cases := []struct {
		visualization string
		want          bool
	}{
		{visualization: "line", want: true},
		{visualization: "timeline", want: true},
		{visualization: "bar", want: false},
		{visualization: "table", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.visualization, func(t *testing.T) {
			columns := explorerColumns(ai.ExplorerQuery{
				Source:        ai.ExplorerFlow,
				Dimensions:    []string{"site"},
				Measures:      []string{"bps"},
				Visualization: tc.visualization,
			})
			got := false
			for _, column := range columns {
				if column.Key == "occurred_at" {
					got = true
					if column.Numeric {
						t.Fatalf("occurred_at column must not be numeric: %+v", column)
					}
				}
			}
			if got != tc.want {
				t.Fatalf("visualization %q occurred_at column = %v, want %v (columns %+v)",
					tc.visualization, got, tc.want, columns)
			}
		})
	}
}

func TestExplorerSemanticTenantFilterFailsClosed(t *testing.T) {
	srv := testServer(fakePinger{})
	for _, key := range []string{"tenant", "tenant_id", "tenant.name"} {
		body := []byte(`{"question":"top talkers","source":"flow","filters":{"` + key + `":"foreign"}}`)
		rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body)))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "authentication") {
			t.Fatalf("filter %q = %d %s", key, rec.Code, rec.Body.String())
		}
	}
}

func TestExplorerTenantBoundaryPrecedesSourceRBAC(t *testing.T) {
	srv := testServer(fakePinger{})
	body := []byte(`{"question":"top talkers","source":"flow"}`)

	missingTenant := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body))
	missingTenant = missingTenant.WithContext(auth.WithPrincipal(missingTenant.Context(), &auth.Principal{
		Permissions: map[string]bool{permAIQuery: true},
	}))
	missingRec := httptest.NewRecorder()
	apiHandler(srv.handleExplorerQuery).ServeHTTP(missingRec, missingTenant)
	if missingRec.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant must fail before source RBAC: %d %s", missingRec.Code, missingRec.Body.String())
	}

	noFlow := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", bytes.NewReader(body))
	noFlow = noFlow.WithContext(auth.WithPrincipal(noFlow.Context(), &auth.Principal{
		TenantID:    "00000000-0000-0000-0000-000000000001",
		Permissions: map[string]bool{permAIQuery: true},
	}))
	noFlowRec := httptest.NewRecorder()
	apiHandler(srv.handleExplorerQuery).ServeHTTP(noFlowRec, noFlow)
	if noFlowRec.Code != http.StatusForbidden {
		t.Fatalf("tenant-bound caller without flow.read = %d %s", noFlowRec.Code, noFlowRec.Body.String())
	}

	comparisonBody := []byte(`{
		"query":{
			"question":"top talkers","source":"flow",
			"from":"2026-07-14T12:00:00Z","to":"2026-07-14T13:00:00Z",
			"measures":["bps"]
		},
		"previous_from":"2026-07-14T10:00:00Z",
		"previous_to":"2026-07-14T11:00:00Z"
	}`)
	missingComparisonTenant := httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(comparisonBody))
	missingComparisonTenant = missingComparisonTenant.WithContext(auth.WithPrincipal(missingComparisonTenant.Context(), &auth.Principal{
		Permissions: map[string]bool{permAIQuery: true},
	}))
	missingComparisonRec := httptest.NewRecorder()
	apiHandler(srv.handleExplorerComparison).ServeHTTP(missingComparisonRec, missingComparisonTenant)
	if missingComparisonRec.Code != http.StatusUnauthorized {
		t.Fatalf("comparison missing tenant must fail before source RBAC: %d %s", missingComparisonRec.Code, missingComparisonRec.Body.String())
	}

	noComparisonFlow := httptest.NewRequest(http.MethodPost, "/v1/explorer/compare", bytes.NewReader(comparisonBody))
	noComparisonFlow = noComparisonFlow.WithContext(auth.WithPrincipal(noComparisonFlow.Context(), &auth.Principal{
		TenantID:    "00000000-0000-0000-0000-000000000001",
		Permissions: map[string]bool{permAIQuery: true},
	}))
	noComparisonFlowRec := httptest.NewRecorder()
	apiHandler(srv.handleExplorerComparison).ServeHTTP(noComparisonFlowRec, noComparisonFlow)
	if noComparisonFlowRec.Code != http.StatusForbidden {
		t.Fatalf("tenant-bound comparison caller without flow.read = %d %s", noComparisonFlowRec.Code, noComparisonFlowRec.Body.String())
	}
}

func TestExplorerABAC(t *testing.T) {
	const tenantID = "00000000-0000-0000-0000-0000000000e1"
	srv := testServer(fakePinger{})
	cache := newClosedABACCache(t)
	cache.data[tenantID] = abacEntry{
		policies: []auth.Policy{{
			Name:       "deny contractor flow",
			Effect:     auth.PolicyDeny,
			Permission: permFlowRead,
			Subject:    map[string]string{"department": "contractor"},
			Priority:   100,
			Enabled:    true,
		}},
		expiry: time.Now().Add(time.Hour),
	}
	srv.abac = cache
	principal := &auth.Principal{
		TenantID: tenantID,
		UserID:   "explorer-contractor",
		Permissions: map[string]bool{
			permAIQuery:  true,
			permFlowRead: true,
		},
		Attributes: map[string]string{"department": "contractor"},
	}

	tests := []struct {
		name string
		path string
		body string
		call apiHandler
	}{
		{
			name: "query",
			path: "/v1/explorer/query",
			body: `{"question":"top talkers","source":"flow"}`,
			call: srv.handleExplorerQuery,
		},
		{
			name: "comparison",
			path: "/v1/explorer/compare",
			body: `{
				"query":{
					"question":"top talkers","source":"flow",
					"from":"2026-07-14T12:00:00Z","to":"2026-07-14T13:00:00Z",
					"measures":["bps"]
				},
				"previous_from":"2026-07-14T10:00:00Z",
				"previous_to":"2026-07-14T11:00:00Z"
			}`,
			call: srv.handleExplorerComparison,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
			rec := httptest.NewRecorder()
			apiHandler(tt.call).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("ABAC-denied Explorer %s = %d %s, want 403 before source dispatch",
					tt.name, rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("policy load failure fails closed", func(t *testing.T) {
		faultSrv := testServer(fakePinger{})
		faultSrv.abac = newClosedABACCache(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/explorer/query",
			strings.NewReader(`{"question":"top talkers","source":"flow"}`))
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		apiHandler(faultSrv.handleExplorerQuery).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("Explorer policy-load failure = %d %s, want 503", rec.Code, rec.Body.String())
		}
	})
}

func TestExplorerSavedViewTenantIsolation(t *testing.T) {
	srv := testServer(fakePinger{})
	body := []byte(`{"surface":"explorer","name":"Cross-AZ cost","filters":{"template":"cross-az-cost","source":"cost"}}`)
	created := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/inventory/views", bytes.NewReader(body)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", created.Code, created.Body.String())
	}
	var view struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/inventory/views/"+view.ID, nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	foreign := doReq(srv, req)
	missing := doReq(srv, httptest.NewRequest(http.MethodGet, "/v1/inventory/views/missing", nil))
	var foreignErr, missingErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(foreign.Body.Bytes(), &foreignErr)
	_ = json.Unmarshal(missing.Body.Bytes(), &missingErr)
	if foreign.Code != http.StatusNotFound || missing.Code != http.StatusNotFound || foreignErr.Error != missingErr.Error {
		t.Fatalf("foreign = %d %q; missing = %d %q", foreign.Code, foreign.Body.String(), missing.Code, missing.Body.String())
	}
}
