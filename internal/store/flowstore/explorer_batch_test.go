// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestExplorerPlanBatchSharesTenantReadAndExecutionEnvelope(t *testing.T) {
	t.Run("success", testPlanBatchEnvelope)
}

func testPlanBatchEnvelope(t *testing.T) {
	store := NewMemory()
	red := explorerFixtureRow("red")
	red.BytesScaled, red.Protocol = 100, "RED_ONLY"
	second := red
	second.SrcPort++
	blue := red
	blue.TenantID, blue.Protocol, blue.BytesScaled = "blue", "BLUE_ONLY", 9007199254740993
	rows := []Row{red, second, blue}
	for i := range 100 {
		foreign := blue
		foreign.SrcPort = uint16(i + 1000)
		rows = append(rows, foreign)
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: red.TS.Add(-time.Minute), To: red.TS.Add(time.Minute), View: "table", GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	budget := DefaultExplorerBudget()
	budget.ReadRows = 3
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	batch, err := NewPlanBatch(ctx, store, "red", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Close)
	if _, ok := batch.Context().Deadline(); !ok {
		t.Fatal("source batch has no operation deadline")
	}
	result, err := batch.ExplorePlan(PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || len(result.Rows) != 1 || result.Rows[0].Group["protocol"] != "RED_ONLY" || result.Totals["bytes:total"] != "200" {
		t.Fatal("foreign input consumed or entered the tenant batch", err)
	}
	if result, err := batch.ExplorePlan(PlanQuery{TenantID: "red", Plan: plan}); !errors.Is(err, ErrExplorerBudget) || len(result.Rows) != 0 {
		t.Fatal("repeated source plan received a fresh read allowance", err)
	}
	for range 2 {
		result, err := store.ExplorePlan(ctx, PlanQuery{TenantID: "red", Plan: plan})
		if err != nil || result.Totals["bytes:total"] != "200" {
			t.Fatal("batch changed standalone query admission", err)
		}
	}
	budget.ReadRows = 4
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	complete, err := NewPlanBatch(ctx, store, "red", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(complete.Close)
	for range 2 {
		result, err := complete.ExplorePlan(PlanQuery{TenantID: "red", Plan: plan})
		if err != nil || result.Totals["bytes:total"] != "200" {
			t.Fatal("complete admitted batch lost exact source values", err)
		}
	}
	if _, err := complete.ExplorePlan(PlanQuery{TenantID: "red", Plan: plan}); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("batch exceeded its declared plan count", err)
	}
}

func TestExplorerPlanBatchRefusesScopeMissingPolicyAndCancellation(t *testing.T) {
	store := NewMemory()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	var absent *Memory
	for _, tc := range []struct {
		ctx    context.Context
		store  Store
		tenant string
		plans  int
	}{{t.Context(), store, "red", 1}, {ctx, store, "blue", 1}, {ctx, store, "red", 0}, {ctx, store, "red", -1}, {ctx, store, "red", int(^uint(0) >> 1)}, {ctx, nil, "red", 1}, {ctx, absent, "red", 1}} {
		if batch, err := NewPlanBatch(tc.ctx, tc.store, tc.tenant, tc.plans); err == nil || batch != nil {
			t.Fatal("unscoped, unwired or unlimited batch accepted")
		}
	}
	batch, err := NewPlanBatch(ctx, store, "red", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Close)
	if nested, err := NewPlanBatch(batch.Context(), store, "red", 1); err == nil || nested != nil {
		t.Fatal("nested batch reset its source envelope")
	}
	if _, err := store.ExplorePlan(batch.Context(), PlanQuery{TenantID: "red"}); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("metadata context bypassed batch query admission", err)
	}
	if _, err := batch.ExplorePlan(PlanQuery{TenantID: "blue"}); !errors.Is(err, ErrNoTenant) {
		t.Fatal("batch accepted a foreign source", err)
	}
	if _, err := batch.ExplorePlan(PlanQuery{TenantID: "red"}); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("failed batch continued with partial work", err)
	}
	closed, err := NewPlanBatch(ctx, store, "red", 1)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if _, err := closed.ExplorePlan(PlanQuery{TenantID: "red"}); !errors.Is(err, context.Canceled) {
		t.Fatal("closed source batch executed", err)
	}
}

func TestExplorerPlanBatchTLSChargesEveryResponseAndRejectsMissingReceipts(t *testing.T) {
	const body = "{\"value\":\"OWN_ONLY\"}\n"
	var summary atomic.Value
	summary.Store("")
	var calls atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get(tenantSettingName) != "red" || r.URL.Query().Get("wait_end_of_query") != "1" {
			t.Error("source batch lost tenant or buffered response contract")
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = r.MultipartForm.RemoveAll() }()
		query := r.FormValue("query")
		if r.FormValue("param_tenant") != "red" || !strings.Contains(query, "max_rows_to_read=") || !strings.Contains(query, "tenant_id={tenant:String}") {
			t.Error("source batch lost bound SQL scope or remaining settings")
		}
		if receipt := summary.Load().(string); receipt != "" {
			w.Header().Set("X-ClickHouse-Summary", receipt)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(upstream.Close)
	store, err := NewClickHouseWithClient(upstream.URL, 0, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.WithTenantScoping(true).WithReader(upstream.Client())
	lane, err := store.readLane(Target{}, "red")
	if err != nil {
		t.Fatal(err)
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows, budget.ReadBytes = 3, 1000
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID("red"))
	for _, receipt := range []string{"", `{}`, `{"read_rows":"1","read_bytes":"-1"}`, `{"read_rows":"01","read_bytes":"1"}`, `{"read_rows":"1","read_rows":"0","read_bytes":"1"}`, `{"read_rows":1,"read_bytes":"1"}`, `{"read_rows":"9223372036854775808","read_bytes":"1"}`} {
		summary.Store(receipt)
		batch, err := NewPlanBatch(ctx, store, "red", 2)
		if err != nil {
			t.Fatal(err)
		}
		settings, err := batch.budget.settings()
		if err != nil {
			t.Fatal(err)
		}
		rows, err := store.explorerQueryRows(batch.queryContext(), Target{}, lane, "red", "SELECT value FROM own WHERE tenant_id={tenant:String} "+settings, chParams{"tenant": "red"})
		batch.Close()
		if !errors.Is(err, ErrExplorerBudget) || rows != nil {
			t.Fatal("invalid source receipt exposed records", err)
		}
	}
	summary.Store(`{"read_rows":"2","read_bytes":"600"}`)
	batch, err := NewPlanBatch(ctx, store, "red", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Close)
	settings, err := batch.budget.settings()
	if err != nil {
		t.Fatal(err)
	}
	sql := "SELECT value FROM own WHERE tenant_id={tenant:String} " + settings
	rows, err := store.explorerQueryRows(batch.queryContext(), Target{}, lane, "red", sql, chParams{"tenant": "red"})
	if err != nil || len(rows) != 1 || rows[0]["value"] != "OWN_ONLY" {
		t.Fatal("complete TLS source response was refused", err)
	}
	limited, _, err := batchQueryLimits(batch.queryContext(), "red", sql)
	if err != nil || !strings.Contains(limited, "max_rows_to_read=1,") || !strings.Contains(limited, "max_bytes_to_read=400,") {
		t.Fatal("next probe did not inherit remaining source limits", err)
	}
	rows, err = store.explorerQueryRows(batch.queryContext(), Target{}, lane, "red", sql, chParams{"tenant": "red"})
	if !errors.Is(err, ErrExplorerBudget) || rows != nil {
		t.Fatal("aggregate source read escaped its envelope", err)
	}
	before := calls.Load()
	if _, _, err := batchQueryLimits(batch.queryContext(), "red", sql+" altered"); err == nil || calls.Load() != before {
		t.Fatal("unrecognized SQL settings admitted")
	}
	t.Logf("TLS receipt simulations: %d bounded requests; actual ClickHouse proof separate", calls.Load())
}

func TestExplorerPlanBatchSummaryAndResponseBounds(t *testing.T) {
	store := NewMemory()
	budget := DefaultExplorerBudget()
	budget.ResponseBytes = 11
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	batch, err := NewPlanBatch(tenancy.WithTenant(t.Context(), tenancy.ID("red")), store, "red", 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Close)
	header := http.Header{}
	header.Set("X-ClickHouse-Summary", `{"read_rows":"0","read_bytes":"0"}`)
	for _, size := range []int64{5, 5} {
		if err := chargeBatchResponse(batch.queryContext(), "red", header, size); err != nil {
			t.Fatal(err)
		}
	}
	if err := chargeBatchResponse(batch.queryContext(), "red", header, 2); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("aggregate response bytes escaped envelope", err)
	}
	for _, raw := range []string{`[]`, `{"read_rows":"0","read_bytes":"0"} trailing`, fmt.Sprintf(`{"read_rows":"%s","read_bytes":"0"}`, strings.Repeat("9", 5000))} {
		header.Set("X-ClickHouse-Summary", raw)
		if err := chargeBatchResponse(batch.queryContext(), "red", header, 0); !errors.Is(err, ErrExplorerBudget) {
			t.Fatal("malformed or oversized source receipt admitted", err)
		}
	}
}
