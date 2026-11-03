// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"slices"
	"strings"
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
	rows, err := lookup.ExternalRows(a, 1<<20)
	if err != nil || !strings.Contains(string(rows), `"lookup_exporter":"192.0.2.10"`) ||
		!strings.Contains(string(rows), `"customer":"blue"`) ||
		!strings.Contains(string(rows), `"lookup_tenant":"`+a+`"`) {
		t.Fatalf("bounded external lookup omitted tenant or tag: %s, %v", rows, err)
	}
	if _, err := lookup.ExternalRows(b, 1<<20); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("foreign tenant serialized tag lookup: %v", err)
	}
	if _, err := lookup.ExternalRows(a, 8); !errors.Is(err, ErrExplorerBudget) {
		t.Fatalf("over-budget external lookup was serialized: %v", err)
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

func TestTagContextAuthorizationIsImmutableAndTenantBound(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	data, err := NewTagQueryData(a, 1, nil, nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	bound, err := data.WithContextAuthorization(a, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bound.ContextAuthorization(a); err != nil || got != digest {
		t.Fatal("context policy binding was lost")
	}
	if _, err := data.ContextAuthorization(a); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("binding mutated an existing lookup")
	}
	if _, err := bound.ContextAuthorization(b); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("context policy binding crossed tenants")
	}
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("AB", 32), strings.Repeat("x", 64)} {
		if _, err := data.WithContextAuthorization(a, value); !errors.Is(err, ErrTagQueryScope) {
			t.Fatal("malformed context binding accepted")
		}
	}
	if _, err := data.WithContextAuthorization(b, digest); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("another tenant attached an authorization binding")
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

func TestClickHouseTagPlanBindsKeyAndJoinsTenantInOneQuery(t *testing.T) {
	tenant := uuid.NewString()
	lookup, err := NewTagQueryData(tenant, 8,
		[]tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}},
		[]tags.ExporterProjection{{Exporter: "192.0.2.1", Values: map[string]string{"customer": "blue"}}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	row := explorerFixtureRow(tenant)
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Hour),
		GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{
			Measure: "bytes", Calculation: "total", Role: "primary"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{
			Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"blue"}}}}}
	if _, _, err := planSQLWithBudget(DefaultExplorerBudget(), plan, "probectl_flows", nil); err == nil {
		t.Fatal("native SQL compiler admitted a tag without its tenant vocabulary")
	}
	sql, params, err := planSQLWithTags(DefaultExplorerBudget(), plan, "probectl_flows", nil,
		tenant, lookup)
	if err != nil || !strings.Contains(sql, "ANY LEFT JOIN tag_lookup") ||
		!strings.Contains(sql, "tag_lookup.lookup_tenant=tenant_id") ||
		!strings.Contains(sql, "toIPv6OrNull(tag_lookup.lookup_exporter)=toIPv6OrNull(exporter)") ||
		!strings.Contains(sql, "tenant_id={tenant:String}") ||
		strings.Contains(sql, "blue") || strings.Contains(sql, "customer") {
		t.Fatalf("tag SQL lost scoped join or embedded a literal: %s, %v", sql, err)
	}
	if params["filter_0_0"] != "blue" || len(params["interfaces"]) == 0 {
		t.Fatalf("tag SQL did not bind filter and metadata: %+v", params)
	}
	if _, _, err := planSQLWithTags(DefaultExplorerBudget(), plan, "probectl_flows", nil,
		uuid.NewString(), lookup); !errors.Is(err, ErrTagQueryScope) {
		t.Fatalf("foreign tenant compiled this tag query: %v", err)
	}
}

func TestSubjectTagDimensionsKeepIndependentValuesForTheSameDefinition(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	id := uuid.NewString()
	values := map[string]string{"customer": "exporter", "device.customer": "device", "agent.customer": "collector"}
	lookup, err := NewTagQueryData(a, 9, []tags.Definition{{TenantID: a, ID: id, Key: "customer"}}, []tags.ExporterProjection{{Exporter: "192.0.2.1", Values: values}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	values["device.customer"] = "caller-mutation"
	if got, err := lookup.Value(a, "192.0.2.1", "device.customer"); err != nil || got != "device" {
		t.Fatal("caller changed a qualified tag lookup")
	}
	row := explorerFixtureRow(a)
	row.AgentID = "forged-other-agent"
	row.BytesScaled = 100
	foreign := row
	foreign.TenantID = b
	foreign.BytesScaled = 900
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{row, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Hour), GroupBy: []string{"tag.customer", "tag.device.customer", "tag.agent.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.device.customer", Op: flow.QueryEqual, Values: []string{"device"}}, {Field: "tag.agent.customer", Op: flow.QueryEqual, Values: []string{"collector"}}}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: a, Plan: plan, Tags: lookup})
	if err != nil || len(result.Rows) != 1 || result.Totals["bytes:total"] != "100" || result.Rows[0].Group["tag.customer"] != "exporter" || result.Rows[0].Group["tag.device.customer"] != "device" || result.Rows[0].Group["tag.agent.customer"] != "collector" {
		t.Fatalf("mixed subject dimensions selected another namespace or tenant: %+v %v", result, err)
	}
	sql, params, err := planSQLWithTags(DefaultExplorerBudget(), plan, "probectl_flows", nil, a, lookup)
	base := "tag_key_" + strings.ReplaceAll(id, "-", "")
	if err != nil || params[base] != "customer" || params[base+"_device"] != "device.customer" || params[base+"_agent"] != "agent.customer" {
		t.Fatalf("same-definition subject parameters overwrote one another: %+v %v", params, err)
	}
	for _, literal := range []string{"customer", "collector", "device.customer", "agent.customer"} {
		if strings.Contains(sql, literal) {
			t.Fatal("tag key/value entered SQL structure")
		}
	}
}

func TestLongTagValuesRemainQueryAndResponseBudgeted(t *testing.T) {
	tenant := uuid.NewString()
	value := strings.Repeat("🌐", 24000)
	definitions := []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}
	projections := []tags.ExporterProjection{{Exporter: "192.0.2.10", Values: map[string]string{"customer": value}}, {Exporter: "192.0.2.11", Values: map[string]string{"customer": "other"}}}
	if _, err := NewTagQueryData(tenant, 2, definitions, projections, int64(len(value))); !errors.Is(err, ErrExplorerBudget) {
		t.Fatalf("long metadata escaped lookup memory budget: %v", err)
	}
	lookup, err := NewTagQueryData(tenant, 2, definitions, projections, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vocabulary, err := lookup.Vocabulary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flow.NormalizeQueryPredicatesWithVocabulary([]flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{value}}}, vocabulary); err != nil {
		t.Fatalf("supported multi-byte tag could not be used as a filter: %v", err)
	}
	if _, err := lookup.ExternalRows(tenant, 1024); !errors.Is(err, ErrExplorerBudget) {
		t.Fatalf("long lookup ignored serialized response budget: %v", err)
	}
	row := explorerFixtureRow(tenant)
	row.Exporter = "192.0.2.10"
	row.BytesScaled = 700
	memory := NewMemory()
	other := row
	other.Exporter = "192.0.2.11"
	other.BytesScaled = 300
	foreign := row
	foreign.TenantID = uuid.NewString()
	foreign.BytesScaled = 1000
	if err := memory.Insert(t.Context(), []Row{row, other, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Minute),
		GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{value}}}}}
	query := PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup}
	result, err := memory.ExplorePlan(t.Context(), query)
	if err != nil || len(result.Rows) != 1 || result.Rows[0].Group["tag.customer"] != value || result.Totals["bytes:total"] != "700" {
		t.Fatalf("long metadata did not group retained traffic: rows=%d err=%v", len(result.Rows), err)
	}
	budget := DefaultExplorerBudget()
	budget.MemoryBytes = 16 << 10
	if err := AttachExplorerBudget(memory, budget); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.ExplorePlan(t.Context(), query); !errors.Is(err, ErrExplorerBudget) {
		t.Fatalf("long group key escaped execution memory accounting: %v", err)
	}
}

func TestInterfaceTagLookupKeepsSidesTenantBudgetAndInputCoverage(t *testing.T) {
	tenant, foreign, id := uuid.NewString(), uuid.NewString(), uuid.NewString()
	definitions := []tags.Definition{{TenantID: tenant, ID: id, Key: "customer"}}
	interfaces := map[uint32]map[string]string{7: {"customer": "input"}, 8: {"customer": "output"}}
	projection := []tags.ExporterProjection{{Exporter: "192.0.2.1", Interfaces: interfaces}}
	lookup, err := NewTagQueryData(tenant, 8, definitions, projection, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	interfaces[7]["customer"] = "caller mutation"
	row := explorerFixtureRow(tenant)
	row.AgentID, row.InIf, row.OutIf, row.BytesScaled = "forged-sender", 7, 8, 100
	value, err := lookup.valueForRow(row, "in_interface.customer")
	if err != nil || value != "input" {
		t.Fatal("caller mutated interface values")
	}
	unmatched := row
	unmatched.InIf, unmatched.BytesScaled = 0, 200
	other := row
	other.TenantID, other.BytesScaled = foreign, 900
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{row, unmatched, other}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: row.TS.Add(-time.Minute), To: row.TS.Add(time.Hour), GroupBy: []string{"tag.in_interface.customer"}, View: "matrix", MatrixWith: []string{"tag.out_interface.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
	if err != nil || result.Totals["bytes:total"] != "300" || len(result.Rows) != 2 || len(result.Matrix) != 2 {
		t.Fatalf("interface tag changed tenant totals: %+v %v", result, err)
	}
	groups := map[string]string{}
	for _, item := range result.Rows {
		groups[item.Group["tag.in_interface.customer"]] = item.Metrics["bytes:total"]
	}
	if groups["input"] != "100" || groups[""] != "200" {
		t.Fatal("input tag selected unmatched/foreign index")
	}
	for _, item := range result.Matrix {
		if item.Column["tag.out_interface.customer"] != "output" {
			t.Fatal("output interface used input value")
		}
	}
	vocabulary, err := lookup.Vocabulary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	queryCtx, err := flow.WithQueryVocabulary(t.Context(), tenant, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := SnapshotInputsForTenant(queryCtx, tenant, result)
	if err != nil || !inputs.NeedsComplete || !inputs.TagLookup || !slices.Equal(inputs.Fields, []string{"exporter", "in_if", "out_if"}) || !slices.Equal(inputs.TagSubjects, []string{"interface"}) {
		t.Fatalf("interface frozen receipt omitted physical input columns: %+v %v", inputs, err)
	}
	plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.in_interface.customer", Op: flow.QueryEqual, Values: []string{"input"}}, {Field: "tag.out_interface.customer", Op: flow.QueryEqual, Values: []string{"output"}}}}
	filtered, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
	if err != nil || filtered.Totals["bytes:total"] != "100" {
		t.Fatal("interface predicate used wrong side")
	}
	sql, params, err := planSQLWithTags(DefaultExplorerBudget(), plan, "probectl_flows", nil, tenant, lookup)
	base := "tag_key_" + strings.ReplaceAll(id, "-", "")
	if err != nil || params[base+"_in_interface"] != "customer" || params[base+"_out_interface"] != "customer" || !strings.Contains(sql, "toString(in_if)") || !strings.Contains(sql, "toString(out_if)") || strings.Contains(sql, "customer") {
		t.Fatalf("interface SQL lost bound independent side keys: %v", err)
	}
	if _, err := lookup.valueForRow(other, "in_interface.customer"); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("foreign row reused interface lookup")
	}
	if _, err := NewTagQueryData(tenant, 1, definitions, []tags.ExporterProjection{{Exporter: "192.0.2.1", Interfaces: map[uint32]map[string]string{0: {"customer": "untrusted"}}}}, 1<<20); !errors.Is(err, ErrTagQueryScope) {
		t.Fatal("zero index entered interface lookup")
	}
	if _, err := NewTagQueryData(tenant, 1, definitions, []tags.ExporterProjection{{Exporter: "192.0.2.1", Interfaces: map[uint32]map[string]string{7: {"customer": strings.Repeat("x", 4096)}}}}, 1024); !errors.Is(err, ErrExplorerBudget) {
		t.Fatal("interface metadata escaped query memory budget")
	}
}
