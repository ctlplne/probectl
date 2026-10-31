// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

func TestExplorerBudgetPreservesDefaultsAndRejectsUnlimited(t *testing.T) {
	defaults := DefaultExplorerBudget()
	settings, err := defaults.settings()
	if err != nil || settings != planCostSettings {
		t.Fatal("default query settings changed", err)
	}
	for _, field := range []string{"duration", "read-bytes", "read-rows", "response", "memory", "groups", "interfaces", "threads", "sentinel"} {
		t.Run(field, func(t *testing.T) {
			budget := defaults
			switch field {
			case "duration":
				budget.ExecutionLimit = 0
			case "read-bytes":
				budget.ReadBytes = 0
			case "read-rows":
				budget.ReadRows = -1
			case "response":
				budget.ResponseBytes = 0
			case "memory":
				budget.MemoryBytes = 0
			case "groups":
				budget.IntermediateGroups = 0
			case "interfaces":
				budget.InterfaceItems = 0
			case "threads":
				budget.Threads = 0
			case "sentinel":
				budget.ResponseBytes = int64(^uint(0) >> 1)
			}
			if budget.Validate() == nil {
				t.Fatal("unlimited or overflowing budget accepted")
			}
			if sql, err := budget.settings(); err == nil || sql != "" {
				t.Fatal("invalid budget produced SQL settings")
			}
		})
	}
	budget := defaults
	budget.ExecutionLimit = time.Second + time.Nanosecond
	settings, err = budget.settings()
	if err != nil || !strings.Contains(settings, "max_execution_time=1.000000001,") {
		t.Fatal("fractional deadline lost precision", err)
	}
}

func TestExplorerConfiguredSQLAndTLSResponseBudgets(t *testing.T) {
	budget := DefaultExplorerBudget()
	budget.ExecutionLimit = 1250 * time.Millisecond
	budget.ReadBytes, budget.ReadRows = 123456, 1234
	budget.MemoryBytes, budget.IntermediateGroups, budget.Threads = 987654, 4321, 3
	row := explorerFixtureRow("red")
	plan := flow.QueryPlan{From: row.TS, To: row.TS.Add(time.Minute), View: "table", GroupBy: []string{"src_port"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	sql, _, err := planSQLWithBudget(budget, plan, "probectl_flows", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"max_execution_time=1.25,", "max_bytes_to_read=123456,", "max_rows_to_read=1234,", "max_memory_usage=987654,", "max_rows_to_group_by=4321,", "max_threads=3", "tenant_id={tenant:String}"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("configured policy or tenant predicate absent: %s", want)
		}
	}

	const body = "{\"value\":\"own exact result\"}\n"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(tenantSettingName) == "red" {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			reader, err := r.MultipartReader()
			if err != nil {
				t.Error("invalid bounded query multipart body")
				return
			}
			tenant := ""
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Error("invalid bounded query multipart part")
					return
				}
				if part.FormName() == "param_tenant" {
					value, err := io.ReadAll(io.LimitReader(part, 65))
					if err != nil || len(value) > 64 {
						t.Error("invalid bounded query tenant part")
					}
					tenant = string(value)
				}
				if err := part.Close(); err != nil {
					t.Error("query multipart part close failed")
				}
			}
			if tenant != "red" {
				t.Error("query lost its separately bound tenant")
			}
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(upstream.Close)
	store, err := NewClickHouseWithClient(upstream.URL, 0, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.WithTenantScoping(true).WithReader(upstream.Client())
	target := Target{} // Pooled reader; an explicit routed URL requires its own DB.
	lane, err := store.readLane(target, "red")
	if err != nil {
		t.Fatal(err)
	}
	budget.ResponseBytes = int64(len(body) - 1)
	ctx := withExplorerBudget(t.Context(), budget)
	rows, err := store.explorerQueryRows(ctx, target, lane, "red", sql, chParams{"tenant": "red"})
	if !errors.Is(err, chclient.ErrResponseTooLarge) || rows != nil {
		t.Fatal("oversized TLS response exposed partial records", err)
	}
	budget.ResponseBytes = int64(len(body))
	rows, err = store.explorerQueryRows(withExplorerBudget(t.Context(), budget), target, lane, "red", sql, chParams{"tenant": "red"})
	if err != nil || len(rows) != 1 || rows[0]["value"] != "own exact result" {
		t.Fatal("exact configured response was not admitted", err)
	}
}

func TestExplorerConfiguredMemoryBudgetCountsOwnRowsFirst(t *testing.T) {
	store := NewMemory()
	first := explorerFixtureRow("red")
	second := first
	second.SrcPort++
	rows := []Row{first, second}
	for i := range 100 {
		foreign := first
		foreign.TenantID = "blue"
		foreign.SrcPort = uint16(i)
		rows = append(rows, foreign)
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: first.TS.Add(-time.Minute), To: first.TS.Add(time.Minute), GroupBy: []string{"src_port"}, View: "table", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	budget := DefaultExplorerBudget()
	budget.ReadRows = 1
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan}); !errors.Is(err, ErrExplorerBudget) || len(result.Rows) != 0 {
		t.Fatal("configured examined-row budget did not refuse atomically", err)
	}
	budget.ReadRows = 2
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan})
	if err != nil || len(result.Rows) != 2 {
		t.Fatal("foreign tenant rows consumed the own-tenant budget", err)
	}
	budget.IntermediateGroups = 1
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: "red", Plan: plan}); !errors.Is(err, ErrExplorerBudget) || len(result.Rows) != 0 {
		t.Fatal("configured aggregation budget did not refuse atomically", err)
	}
}
