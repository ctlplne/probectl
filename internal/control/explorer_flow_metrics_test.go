// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type metricPlanStore struct {
	*flowstore.Memory
	explore func(context.Context, flowstore.PlanQuery) (flowstore.PlanResult, error)
}

func (s *metricPlanStore) ExplorePlan(ctx context.Context, q flowstore.PlanQuery) (flowstore.PlanResult, error) {
	return s.explore(ctx, q)
}

func TestNativeFlowMetricsSharedServicesStayTenantFreeAndCountOnce(t *testing.T) {
	const red, blue = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	store := flowstore.NewMemory()
	if err := store.Insert(t.Context(), []flowstore.Row{{TenantID: red, TS: at, Protocol: "metrics-private-red", BytesScaled: 100}, {TenantID: blue, TS: at, Protocol: "metrics-private-blue", BytesScaled: 200}, {TenantID: blue, TS: at.Add(time.Second), Protocol: "metrics-private-blue", BytesScaled: 300}}); err != nil {
		t.Fatal(err)
	}
	budget := flowstore.DefaultExplorerBudget()
	budget.ReadRows = 1
	if err := flowstore.AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	s := testServer(fakePinger{}).WithFlowStore(store)
	// Exercise the production scrape guard rather than the explicit dev-mode bypass.
	s.cfg.AuthMode = "session"
	s.cfg.MetricsScrapeToken = "owned-query-metrics-proof"
	query, err := ai.NormalizeExplorerQuery(ai.ExplorerQuery{Question: "metrics-private-question", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, View: "table", RowLimit: 10, PageSize: 10, BucketSeconds: 60, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := &auth.Principal{TenantID: red, UserID: "metrics-private-user", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}}
	w := httptest.NewRecorder()
	if err := s.handleRecordFlowQuery(w, httptest.NewRequest(http.MethodPost, "/v1/explorer/query", nil), p, query); err != nil || w.Code != 200 {
		t.Fatal("REST service failed", err)
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": query.Flow}}})
	response := nativeControlMCP(t, s).Handle(t.Context(), p, raw)
	if strings.Contains(string(response), `"isError":true`) || strings.Contains(string(response), `"error":`) {
		t.Fatal("native MCP service failed")
	}
	foreign := *p
	foreign.TenantID = blue
	if result, err := s.recordFlowQuery(t.Context(), &foreign, query); err == nil || result.Flow != nil {
		t.Fatal("blue cost refusal returned data")
	}
	if _, err := s.recordFlowQuery(t.Context(), nil, query); err == nil {
		t.Fatal("tenantless query admitted")
	}
	bad := query
	// Normalized envelopes carry the authoritative grouping fields too.
	bad.Groupings, bad.Dimensions = []string{"unknown_field"}, []string{"unknown_field"}
	badPlan := *query.Flow
	badPlan.GroupBy = []string{"unknown_field"}
	bad.Flow = &badPlan
	if _, err := s.recordFlowQuery(t.Context(), p, bad); err == nil {
		t.Fatal("invalid plan admitted")
	}
	if _, err := s.recordFlowComparison(t.Context(), p, query, query); err != nil {
		t.Fatal("comparison failed", err)
	}
	continuation := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: "private-unavailable-cursor"}}
	if _, err := s.resumeFlowSnapshot(t.Context(), p, continuation); err == nil {
		t.Fatal("absent page storage admitted")
	}
	if _, err := s.resumeFlowComparisonSnapshot(t.Context(), p, continuation); err == nil {
		t.Fatal("absent comparison storage admitted")
	}
	if _, err := s.prepareFlowCSVContext(t.Context(), p, "private-snapshot", nil, nil); err == nil {
		t.Fatal("missing durable CSV audit admitted")
	}
	if got := s.flowOperationMetrics["query"].outcomes["success"].Value(); got != 2 {
		t.Fatal("comparison passes or transport wrappers inflated logical query count", got)
	}
	for outcome, count := range map[string]uint64{"budget": 1, "authorization": 1, "validation": 1} {
		if s.flowOperationMetrics["query"].outcomes[outcome].Value() != count {
			t.Fatal("wrong terminal outcome", outcome)
		}
	}
	if s.flowOperationMetrics["comparison"].outcomes["success"].Value() != 1 {
		t.Fatal("comparison was not exactly one service operation")
	}

	// The actual protected TLS scrape has no implicit tenant data privilege.
	server := httptest.NewTLSServer(s.Handler())
	defer server.Close()
	scrape := func(token string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	if status, _ := scrape(""); status == http.StatusOK {
		t.Fatal("anonymous metrics scrape admitted")
	}
	status, body := scrape(s.cfg.MetricsScrapeToken)
	if status != http.StatusOK {
		t.Fatal("credentialed TLS metrics unavailable")
	}
	for _, secret := range []string{red, blue, "metrics-private", "private-unavailable-cursor", "private-snapshot", "tenant_id="} {
		if strings.Contains(body, secret) {
			t.Fatal("metrics exposed tenant/request content", secret)
		}
	}
	for _, want := range []string{`probectl_flow_explorer_query_operations_total{outcome="success"} 2`, `probectl_flow_explorer_query_operations_total{outcome="budget"} 1`, "# TYPE probectl_flow_explorer_query_duration_seconds histogram", "probectl_flow_explorer_query_duration_seconds_count 5"} {
		if !strings.Contains(body, want+"\n") {
			t.Fatal("missing service instrumentation", want)
		}
	}
	for _, operation := range otel.FlowExplorerOperations() {
		if !strings.Contains(body, "probectl_flow_explorer_"+operation+"_active 0\n") {
			t.Fatal("active operation leaked", operation)
		}
	}
}

func TestNativeFlowMetricsCancellationCoverageAndDependencyFailure(t *testing.T) {
	s := testServer(fakePinger{})
	store := &metricPlanStore{Memory: flowstore.NewMemory()}
	s.WithFlowStore(store)
	at := time.Now().UTC().Add(-time.Hour)
	query, err := ai.NormalizeExplorerQuery(ai.ExplorerQuery{Question: "private", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, View: "table", RowLimit: 10, PageSize: 10, BucketSeconds: 60, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", UserID: "private", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}}
	started := make(chan struct{})
	store.explore = func(ctx context.Context, _ flowstore.PlanQuery) (flowstore.PlanResult, error) {
		close(started)
		<-ctx.Done()
		return flowstore.PlanResult{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.recordFlowQuery(ctx, p, query); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("query did not enter source")
	}
	if s.flowOperationMetrics["query"].active.Load() != 1 {
		t.Fatal("in-flight operation not observed")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled query succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled query did not release source")
	}
	for _, failure := range []error{&flowstore.PlanCoverageError{ResolutionSeconds: 60, Reason: "inputs unavailable"}, errors.New("private-backend-password-and-SQL")} {
		store.explore = func(context.Context, flowstore.PlanQuery) (flowstore.PlanResult, error) {
			return flowstore.PlanResult{}, failure
		}
		if _, err := s.recordFlowQuery(t.Context(), p, query); err == nil {
			t.Fatal("failed source succeeded")
		}
	}
	for _, outcome := range []string{"canceled", "coverage", "unavailable"} {
		if s.flowOperationMetrics["query"].outcomes[outcome].Value() != 1 {
			t.Fatal("lost failure classification", outcome)
		}
	}
	if s.flowOperationMetrics["query"].active.Load() != 0 || s.flowOperationMetrics["query"].outcomes["success"].Value() != 0 {
		t.Fatal("failed/canceled operation retained work or recorded success")
	}
}
