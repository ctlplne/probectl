// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagQueryDataBindsTenantAddressAndBudget(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	definitions := []tags.Definition{{TenantID: a, ID: uuid.NewString(), Key: "customer"}}
	projection := []tags.ExporterProjection{{Exporter: "192.0.2.10",
		Values: map[string]string{"customer": "blue"}}}
	lookup, err := NewTagQueryData(a, 8, definitions, projection, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := lookup.Value(a, "192.0.2.10", "customer"); err != nil || value != "blue" {
		t.Fatalf("owned exporter lost its value: %q, %v", value, err)
	}
	if value, err := lookup.Value(a, "192.0.2.11", "customer"); err != nil || value != "" {
		t.Fatalf("unknown exporter was not explicitly unmatched: %q, %v", value, err)
	}
	if _, err := lookup.Value(b, "192.0.2.10", "customer"); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("foreign tenant read tag lookup: %v", err)
	}
	if _, err := NewTagQueryData(a, 8, definitions, projection, 128); !errors.Is(err, ErrExplorerBudget) {
		t.Fatalf("undersized query lookup was accepted: %v", err)
	}
	duplicate := append(append([]tags.ExporterProjection(nil), projection...), projection[0])
	if _, err := NewTagQueryData(a, 8, definitions, duplicate, 1<<20); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("duplicate exporter could select a context: %v", err)
	}
	foreignDefinition := []tags.Definition{{TenantID: b, ID: definitions[0].ID, Key: "customer"}}
	if _, err := NewTagQueryData(a, 8, foreignDefinition, projection, 1<<20); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatalf("foreign tenant's vocabulary was accepted: %v", err)
	}
}

func TestMemoryTagQueryGroupsFiltersAndPreservesTenantTotals(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	definition := tags.Definition{TenantID: a, ID: uuid.NewString(), Key: "customer"}
	lookup, err := NewTagQueryData(a, 8, []tags.Definition{definition},
		[]tags.ExporterProjection{{Exporter: "192.0.2.1", Values: map[string]string{"customer": "blue"}}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	mapped := explorerFixtureRow(a)
	mapped.AgentID = "forged-agent-claim"
	mapped.BytesScaled = 100
	unmatched := mapped
	unmatched.Exporter = "192.0.2.2"
	unmatched.SrcPort++
	unmatched.BytesScaled = 200
	foreign := mapped
	foreign.TenantID = b
	foreign.BytesScaled = 900
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{mapped, unmatched, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: mapped.TS.Add(-time.Minute), To: mapped.TS.Add(time.Hour),
		GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{
			{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: lookup})
	if err != nil || result.TagRevision != 8 || len(result.Rows) != 2 || result.Totals["bytes:total"] != "300" {
		t.Fatalf("tag grouping lost exact tenant totals: %+v, %v", result, err)
	}
	groups := map[string]string{}
	for _, row := range result.Rows {
		groups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
	}
	if groups["blue"] != "100" || groups[""] != "200" {
		t.Fatalf("tag grouping selected a claim or foreign row: %+v", groups)
	}
	plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{
		Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"blue"}}}}
	filtered, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: lookup})
	if err != nil || filtered.Totals["bytes:total"] != "100" || len(filtered.Rows) != 1 {
		t.Fatalf("tag predicate did not filter before aggregation: %+v, %v", filtered, err)
	}
	if _, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: b, Plan: plan, Tags: lookup}); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("another tenant queried this tag snapshot: %v", err)
	}
}
