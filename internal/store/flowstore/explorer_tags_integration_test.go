// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

// This real ClickHouse receipt proves the request-local multipart table,
// tenant/address join, current-rule history semantics and raw/rollup parity.
func TestExplorerClickHouseTagExternalLookupRealStack(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	a, b := uuid.NewString(), uuid.NewString()
	t.Cleanup(func() {
		cleanupExplorerFixtureTenant(t, store, a)
		cleanupExplorerFixtureTenant(t, store, b)
	})
	mapped := explorerFixtureRow(a)
	mapped.AgentID = "untrusted-claim-b"
	mapped.BytesScaled = 100
	unmatched := mapped
	unmatched.Exporter, unmatched.SrcPort, unmatched.BytesScaled = "192.0.2.2", mapped.SrcPort+1, 200
	foreign := mapped
	foreign.TenantID, foreign.BytesScaled = b, 900
	if err := store.Insert(t.Context(), []Row{mapped, unmatched, foreign}); err != nil {
		t.Fatal(err)
	}
	definitionA := tags.Definition{TenantID: a, ID: uuid.NewString(), Key: "customer"}
	lookup := func(tenant string, definition tags.Definition, value string, revision int64) *TagQueryData {
		t.Helper()
		result, err := NewTagQueryData(tenant, revision, []tags.Definition{definition},
			[]tags.ExporterProjection{{Exporter: mapped.Exporter,
				Values: map[string]string{"customer": value}}}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := lookup(a, definitionA, "blue", 8)
	plan := flow.QueryPlan{From: mapped.TS.Add(-time.Minute), To: mapped.TS.Add(time.Hour),
		GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{
			Measure: "bytes", Calculation: "total", Role: "primary"}}}
	for _, source := range []string{"raw", "rollup"} {
		plan.DataSeries = source
		result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: first})
		if err != nil || result.TagRevision != 8 || result.Totals["bytes:total"] != "300" ||
			len(result.Rows) != 2 {
			t.Fatalf("%s tag lookup lost exact tenant rows: %+v, %v", source, result, err)
		}
		groups := map[string]string{}
		for _, row := range result.Rows {
			groups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
		}
		if groups["blue"] != "100" || groups[""] != "200" {
			t.Fatalf("%s tag lookup selected a claimed agent or foreign tenant: %+v", source, groups)
		}
	}
	changed := lookup(a, definitionA, "green", 9)
	plan.DataSeries = "raw"
	retagged, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: changed})
	if err != nil || retagged.TagRevision != 9 || retagged.Totals["bytes:total"] != "300" ||
		len(retagged.Rows) != 2 {
		t.Fatalf("current rule did not re-tag retained history: %+v, %v", retagged, err)
	}
	values := map[string]string{}
	for _, row := range retagged.Rows {
		values[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
	}
	if values["green"] != "100" || values[""] != "200" {
		t.Fatalf("new revision changed totals or kept an old label: %+v", values)
	}
	if _, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: b, Plan: plan, Tags: first}); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("foreign tenant reused a tag lookup: %v", err)
	}
	bLookup := lookup(b, tags.Definition{TenantID: b, ID: uuid.NewString(), Key: "customer"}, "red", 3)
	bResult, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: b, Plan: plan, Tags: bLookup})
	if err != nil || bResult.Totals["bytes:total"] != "900" || len(bResult.Rows) != 1 ||
		bResult.Rows[0].Group["tag.customer"] != "red" {
		t.Fatalf("tenant B lost its same-address label: %+v, %v", bResult, err)
	}
}

func TestExplorerClickHouseRelatedTagNamespacesUseOneTenantExporterJoin(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	a, b := uuid.NewString(), uuid.NewString()
	t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, a); cleanupExplorerFixtureTenant(t, store, b) })
	row := explorerFixtureRow(a)
	row.BytesScaled = 123
	row.AgentID = "forged-payload-agent"
	foreign := row
	foreign.TenantID = b
	foreign.BytesScaled = 900
	if err := store.Insert(t.Context(), []Row{row, foreign}); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	lookup, err := NewTagQueryData(a, 7, []tags.Definition{{TenantID: a, ID: id, Key: "customer"}}, []tags.ExporterProjection{{Exporter: row.Exporter, Values: map[string]string{"customer": "exporter", "device.customer": "device", "agent.customer": "agent"}}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Hour), GroupBy: []string{"tag.customer", "tag.device.customer"}, MatrixWith: []string{"tag.agent.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.device.customer", Op: flow.QueryEqual, Values: []string{"device"}}, {Field: "tag.agent.customer", Op: flow.QueryEqual, Values: []string{"agent"}}}}}
	result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: lookup})
	if err != nil || result.Totals["bytes:total"] != "123" || len(result.Rows) != 1 || result.Rows[0].Group["tag.customer"] != "exporter" || result.Rows[0].Group["tag.device.customer"] != "device" {
		t.Fatalf("actual external tag lookup overwrote a namespace or multiplied tenant rows: %+v %v", result, err)
	}
	if len(result.Matrix) != 1 || result.Matrix[0].Column["tag.agent.customer"] != "agent" {
		t.Fatal("matrix column did not retain its independent subject value")
	}
}
