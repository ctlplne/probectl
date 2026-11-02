// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestSavedQueryViewPinsTenantTagIdentityAndExpandedReferences(t *testing.T) {
	tenant, foreign := uuid.NewString(), uuid.NewString()
	firstID, replacementID := uuid.NewString(), uuid.NewString()
	vocabulary, err := NewTagQueryVocabulary(tenant, []tags.Definition{{TenantID: tenant, ID: firstID, Key: "customer"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := WithQueryVocabulary(t.Context(), tenant, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	definition := queryViewFixture()
	definition.Plan.GroupBy[0] = "tag.customer"
	definition.Plan.Filter = &QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "reference"}}}
	filters := savedFilterFixture{tenant: {"reference": {ID: "reference", TenantID: tenant, Version: 1,
		Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "tag.customer", Op: QueryEqual, Values: []string{"blue"}}}}}}}
	resolved, err := ResolveQueryFiltersWithVocabulary(ctx, tenant, definition.Plan.Filter, filters, "", vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	plan := definition.Plan
	plan.Filter = resolved.Expression
	definition.TagIDs, err = QueryViewTagIDs(plan, vocabulary)
	if err != nil || definition.TagIDs["tag.customer"] != firstID {
		t.Fatalf("saved tag binding missing: %+v, %v", definition.TagIDs, err)
	}
	store := NewMemoryQueryViewStore(filters, 0)
	if _, err := store.SaveQueryView(t.Context(), tenant, "owner", SaveQueryView{Definition: definition}); err == nil {
		t.Fatal("native-only store accepted a tag view")
	}
	saved, err := store.SaveQueryView(ctx, tenant, "owner", SaveQueryView{Definition: definition})
	if err != nil || saved.Definition.TagIDs["tag.customer"] != firstID {
		t.Fatalf("tenant tag view failed to save: %+v, %v", saved, err)
	}
	if _, err := store.GetQueryView(ctx, foreign, "owner", saved.ID); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatalf("foreign tenant could read saved view: %v", err)
	}
	replacement, err := NewTagQueryVocabulary(tenant, []tags.Definition{{TenantID: tenant, ID: replacementID, Key: "customer"}})
	if err != nil {
		t.Fatal(err)
	}
	replacedCtx, err := WithQueryVocabulary(t.Context(), tenant, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQueryViewTagsForTenant(replacedCtx, tenant, saved.Definition, filters); !errors.Is(err, ErrQueryViewStaleTag) {
		t.Fatalf("replacement retargeted saved tag view: %v", err)
	}
	filters[tenant]["reference"] = SavedQueryFilter{ID: "reference", TenantID: tenant, Version: 2,
		Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "tag.other", Op: QueryEqual, Values: []string{"blue"}}}}}
	if err := validateQueryViewTagsForTenant(ctx, tenant, saved.Definition, filters); err == nil {
		t.Fatal("changed saved reference bypassed the pinned tag vocabulary")
	}
}

func queryViewFixture() QueryViewDefinition {
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	return QueryViewDefinition{Name: "Complete query", Visibility: "private", Labels: []string{"edge", "core", "edge"}, Time: QueryViewTime{Mode: "absolute"}, Plan: QueryPlan{From: at.AddDate(0, 0, -401), To: at, GroupBy: []string{"src_addr", "dst_addr", "src_port", "dst_port", "protocol", "exporter", "in_if", "out_if"}, View: "table", RowLimit: 50000, PageSize: 5000, Metrics: []QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bps", Calculation: "p99", Role: "secondary"}}, Filter: &QueryFilterGroup{Match: "any", Groups: []QueryFilterGroup{{Conditions: []QueryPredicate{{Field: "src_addr", Op: QueryCIDR, Values: []string{"192.0.2.0/24"}}}}, {Mode: "exclude", Conditions: []QueryPredicate{{Field: "protocol", Op: QueryRegex, Values: []string{"^sflow"}}}}}}}}
}

func TestQueryViewPreservesCompleteGrammarAndMaterializesRelativeWindows(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	definition := queryViewFixture()
	saved, err := NormalizeSaveQueryView(SaveQueryView{Definition: definition}, now)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Definition.Plan.RowLimit != 50000 || len(saved.Definition.Plan.GroupBy) != 8 || saved.Definition.Plan.Filter == nil || saved.Definition.Plan.To.Sub(saved.Definition.Plan.From) != 401*24*time.Hour || !reflect.DeepEqual(saved.Definition.Labels, []string{"core", "edge"}) {
		t.Fatal("saved query narrowed/truncated grammar")
	}
	definition.Time = QueryViewTime{Mode: "lookback", LookbackSeconds: 401 * 24 * 3600}
	definition.Comparison = &QueryViewComparison{Mode: "preceding"}
	definition.AutoRefreshSeconds = 60
	normalized, err := NormalizeQueryViewDefinition(definition, now)
	if err != nil || !normalized.Plan.From.IsZero() || !normalized.Plan.To.IsZero() || !normalized.Comparison.From.IsZero() {
		t.Fatalf("relative stored as stale absolute time: %+v %v", normalized, err)
	}
	next := now.Add(24 * time.Hour)
	current, previous, err := MaterializeQueryView(normalized, next)
	if err != nil || !current.To.Equal(next) || previous == nil || !previous.To.Equal(current.From) || current.To.Sub(current.From) != previous.To.Sub(previous.From) {
		t.Fatal("relative comparison clock changed", err)
	}
	for _, mutate := range []func(*QueryViewDefinition){
		func(v *QueryViewDefinition) { v.Plan.Cursor = "private-result-cursor" },
		func(v *QueryViewDefinition) { v.Plan.GroupBy = []string{"tenant_id"} },
		func(v *QueryViewDefinition) { v.Visibility = "public" },
		func(v *QueryViewDefinition) { v.Time.LookbackSeconds = -1 },
		func(v *QueryViewDefinition) { v.AutoRefreshSeconds = 1 },
		func(v *QueryViewDefinition) { v.Comparison = &QueryViewComparison{Mode: "preceding", From: now} },
	} {
		invalid := queryViewFixture()
		mutate(&invalid)
		if _, err := NormalizeQueryViewDefinition(invalid, now); err == nil {
			t.Fatal("unsafe/inconsistent saved query accepted")
		}
	}
}

func TestQueryViewDisplayPreservesTypedSettingsWithoutChangingDataAuthority(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	base := queryViewFixture()
	plain, err := NormalizeQueryViewDefinition(base, now)
	if err != nil || plain.Display != nil {
		t.Fatal("legacy view gained display settings", err)
	}
	base.Display = &QueryViewDisplay{TotalOverlay: true, LogMetrics: []string{"bps:p99", "bytes:total", "bps:p99"}, SyncAxes: true, OneChartPerSeries: true, ChartsPerRow: 4, ChartHeight: "tall"}
	got, err := NormalizeQueryViewDefinition(base, now)
	if err != nil || got.Display == nil || !got.Display.TotalOverlay || !got.Display.SyncAxes || !got.Display.OneChartPerSeries || got.Display.ChartsPerRow != 4 || got.Display.ChartHeight != "tall" || !reflect.DeepEqual(got.Display.LogMetrics, []string{"bps:p99", "bytes:total"}) {
		t.Fatalf("display settings lost: %+v %v", got.Display, err)
	}
	if !reflect.DeepEqual(got.Plan, plain.Plan) || len(base.Display.LogMetrics) != 3 {
		t.Fatal("display changed data grammar or mutated input")
	}
	base.Display = &QueryViewDisplay{}
	got, err = NormalizeQueryViewDefinition(base, now)
	if err != nil || got.Display.ChartsPerRow != 1 || got.Display.ChartHeight != "medium" || got.Display.TimeStyle != "line" || got.Display.PercentBasis != "returned" || got.Display.HorizonScale != "shared" || got.Display.LogMetrics == nil {
		t.Fatal("display defaults missing", err)
	}
	for _, bad := range []QueryViewDisplay{{HorizonScale: "other tenants"}, {HorizonScale: "per-request"}, {PercentBasis: "all tenants"}, {PercentBasis: "total"}, {TimeStyle: "sql"}, {TimeStyle: "stacked-area"}, {ChartsPerRow: 5}, {ChartsPerRow: -1}, {ChartHeight: "arbitrary CSS"}, {LogMetrics: []string{"tenant_id:total"}}, {LogMetrics: []string{"packets:avg"}}, {LogMetrics: []string{"bytes:total", "bytes:total", "bytes:total", "bytes:total", "bytes:total"}}} {
		base.Display = &bad
		if _, err := NormalizeQueryViewDefinition(base, now); err == nil {
			t.Fatalf("invalid display accepted: %+v", bad)
		}
	}
}

func TestQueryViewMemoryTenantOwnerSharingVersionsPreferencesAndQuota(t *testing.T) {
	ctx := t.Context()
	store := NewMemoryQueryViewStore(nil, 0)
	first, err := store.SaveQueryView(ctx, "red", "alice", SaveQueryView{Definition: queryViewFixture()})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range [][2]string{{"blue", "alice"}, {"red", "bob"}} {
		if _, err := store.GetQueryView(ctx, scope[0], scope[1], first.ID); !errors.Is(err, ErrQueryViewNotFound) {
			t.Fatal("private view escaped scope", err)
		}
	}
	first.Definition.Plan.Filter.Groups[0].Conditions[0].Values[0] = "mutated"
	own, err := store.GetQueryView(ctx, "red", "alice", first.ID)
	if err != nil || own.Definition.Plan.Filter.Groups[0].Conditions[0].Values[0] == "mutated" {
		t.Fatal("caller mutated owned storage")
	}
	input := SaveQueryView{ID: own.ID, Version: own.Version, Definition: own.Definition}
	input.Definition.Visibility = "tenant"
	shared, err := store.SaveQueryView(ctx, "red", "alice", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetQueryView(ctx, "red", "bob", shared.ID); err != nil {
		t.Fatal("shared same-tenant query unavailable", err)
	}
	if _, err := store.SaveQueryView(ctx, "red", "bob", SaveQueryView{ID: shared.ID, Version: shared.Version, Definition: shared.Definition}); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatal("shared read became ownership", err)
	}
	favorite := true
	if err := store.SetQueryViewPreference(ctx, "red", "bob", shared.ID, &favorite, true); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "favorites", Label: "edge", Search: "complete"})
	if err != nil || len(page.Items) != 1 || !page.Items[0].Favorite || page.Items[0].LastOpenedAt == nil {
		t.Fatal("private preference/list missing", err)
	}
	alice, _ := store.GetQueryView(ctx, "red", "alice", shared.ID)
	if alice.Favorite || alice.LastOpenedAt != nil {
		t.Fatal("preferences crossed owners")
	}
	if _, err := store.SaveQueryView(ctx, "red", "alice", input); !errors.Is(err, ErrQueryViewConflict) {
		t.Fatal("stale version accepted", err)
	}
	// Explicitly cross JavaScript's exact integer range, without a float.
	stored := store.byTenant["red"][shared.ID]
	stored.Version = "9007199254740993"
	store.byTenant["red"][shared.ID] = stored
	updated, err := store.SaveQueryView(ctx, "red", "alice", SaveQueryView{ID: stored.ID, Version: stored.Version, Definition: stored.Definition})
	if err != nil || updated.Version != "9007199254740994" {
		t.Fatal("version rounded", err)
	}
	if err := store.DeleteQueryView(ctx, "blue", "alice", shared.ID, updated.Version); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatal("delete crossed tenants", err)
	}
	if err := store.DeleteQueryView(ctx, "red", "alice", shared.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	page, err = store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "recents"})
	if err != nil || len(page.Items) != 0 {
		t.Fatal("deleted view remained in private recents")
	}
	tiny := NewMemoryQueryViewStore(nil, 1)
	if _, err := tiny.SaveQueryView(ctx, "red", "alice", SaveQueryView{Definition: queryViewFixture()}); !errors.Is(err, ErrQueryViewBudget) {
		t.Fatal("quota silently bypassed", err)
	}
}

func TestQueryViewTimeStyleRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, style := range []string{"line", "stacked_area", "stacked_columns", "percent_area", "horizon"} {
		base := queryViewFixture()
		encoded, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		wire["display"] = map[string]any{"time_style": style, "percent_basis": "visible", "horizon_scale": "lane"}
		encoded, err = json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &base); err != nil {
			t.Fatal(err)
		}
		got, err := NormalizeQueryViewDefinition(base, now)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err = json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"percent_basis":"visible"`) {
			t.Fatal("saved percentage basis lost")
		}
		if !strings.Contains(string(encoded), `"time_style":"`+style+`"`) {
			t.Fatalf("saved time style lost: %s", style)
		}
	}
}

// Saved horizon presentation never changes the query plan or source authority.
func TestQueryViewHorizonScaleSurvivesNormalization(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, style := range []string{"line", "horizon"} {
		definition := queryViewFixture()
		plain, err := NormalizeQueryViewDefinition(definition, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(`{"time_style":"`+style+`","horizon_scale":"lane"}`), &definition.Display); err != nil {
			t.Fatal(err)
		}
		normalized, err := NormalizeQueryViewDefinition(definition, now)
		if err != nil {
			t.Fatalf("horizon display was rejected: %v", err)
		}
		encoded, err := json.Marshal(normalized.Display)
		if err != nil || !strings.Contains(string(encoded), `"horizon_scale":"lane"`) {
			t.Fatalf("horizon scale lost: %s %v", encoded, err)
		}
		if !reflect.DeepEqual(normalized.Plan, plain.Plan) {
			t.Fatal("horizon changed query authority")
		}
	}
}
