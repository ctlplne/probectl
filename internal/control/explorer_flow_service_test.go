// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestNativeFlowTypedServiceScopesBeforeTransport(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	store := flowstore.NewMemory()
	if err := store.Insert(t.Context(), []flowstore.Row{
		{TenantID: red, TS: at, Protocol: "RED_CONTEXT_ONLY", BytesScaled: 9007199254740993},
		{TenantID: blue, TS: at, Protocol: "BLUE_CONTEXT_ONLY", BytesScaled: 9007199254740994},
	}); err != nil {
		t.Fatal(err)
	}
	server := testServer(fakePinger{}).WithFlowStore(store)
	query, err := ai.NormalizeExplorerQuery(ai.ExplorerQuery{
		Question: "Read own protocol traffic", Source: ai.ExplorerFlow,
		From: at.Add(-time.Minute), To: at.Add(time.Minute),
		Dimensions: []string{"protocol"}, Groupings: []string{"protocol"}, Measures: []string{"bytes"},
		Flow: &flow.QueryPlan{RowLimit: 2, PageSize: 2},
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tenant, want, foreign, exact string }{
		{red, "RED_CONTEXT_ONLY", "BLUE_CONTEXT_ONLY", "9007199254740993"},
		{blue, "BLUE_CONTEXT_ONLY", "RED_CONTEXT_ONLY", "9007199254740994"},
	} {
		principal := &auth.Principal{TenantID: tc.tenant, UserID: "reader", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}}
		result, err := server.recordFlowQuery(t.Context(), principal, query)
		if err != nil {
			t.Fatal(err)
		}
		if result.Flow == nil || len(result.Flow.Rows) != 1 || result.Flow.Rows[0].Group["protocol"] != tc.want || result.Flow.Rows[0].Metrics["bytes:total"] != tc.exact {
			t.Fatalf("typed tenant read changed scope/precision: %+v", result)
		}
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), tc.foreign) || strings.Contains(string(body), tc.tenant) {
			t.Fatalf("typed projection exposed foreign data/private scope: %s", body)
		}
	}

	// Call services directly: no HTTP middleware can supply the missing checks.
	for _, principal := range []*auth.Principal{
		nil,
		{UserID: "reader", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}},
		{TenantID: red, UserID: "reader", Permissions: map[string]bool{permAIQuery: true}},
		{TenantID: red, UserID: "reader", Permissions: map[string]bool{permFlowRead: true}},
	} {
		if got, err := server.recordFlowQuery(t.Context(), principal, query); err == nil || got.Flow != nil {
			t.Fatal("typed query bypassed tenant/source authorization")
		}
		if got, err := server.recordFlowComparison(t.Context(), principal, query, query); err == nil || got.Flow != nil {
			t.Fatal("typed comparison bypassed tenant/source authorization")
		}
	}
}

// Dynamic interface assertion gives a behavioral before failure even before the
// native service methods exist; no HTTP recorder or middleware participates.
type nativeFlowFilterContextService interface {
	listFlowFilters(context.Context, *auth.Principal, string, int) (flow.QueryFilterPage, error)
	getFlowFilter(context.Context, *auth.Principal, string) (flow.SavedQueryFilter, error)
	saveFlowFilterDefinition(context.Context, *auth.Principal, flow.SaveQueryFilter) (flow.SavedQueryFilter, error)
	deleteFlowFilter(context.Context, *auth.Principal, string, []string) error
}
type observedNativeFilters struct {
	flow.QueryFilterStore
	calls int
	actor string
}

func (s *observedNativeFilters) GetQueryFilter(ctx context.Context, tenant, id string) (flow.SavedQueryFilter, error) {
	s.calls++
	return s.QueryFilterStore.GetQueryFilter(ctx, tenant, id)
}
func (s *observedNativeFilters) ListQueryFilters(ctx context.Context, tenant, after string, limit int) (flow.QueryFilterPage, error) {
	s.calls++
	return s.QueryFilterStore.ListQueryFilters(ctx, tenant, after, limit)
}
func (s *observedNativeFilters) SaveQueryFilter(ctx context.Context, tenant, actor string, input flow.SaveQueryFilter) (flow.SavedQueryFilter, error) {
	s.calls++
	s.actor = actor
	return s.QueryFilterStore.SaveQueryFilter(ctx, tenant, actor, input)
}
func (s *observedNativeFilters) DeleteQueryFilter(ctx context.Context, tenant, actor, id string, version int64) error {
	s.calls++
	s.actor = actor
	return s.QueryFilterStore.DeleteQueryFilter(ctx, tenant, actor, id, version)
}

func TestNativeFlowFilterContextServiceScopesBeforeStore(t *testing.T) {
	store := &observedNativeFilters{QueryFilterStore: flow.NewMemoryQueryFilterStore(0)}
	server := testServer(fakePinger{}).WithFlowQueryFilters(store)
	api, ok := any(server).(nativeFlowFilterContextService)
	if !ok {
		t.Fatal("native filter context services unavailable")
	}
	principal := func(tenant string) *auth.Principal {
		return &auth.Principal{TenantID: tenant, UserID: "reader", Email: "owner@example.test", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permFlowFiltersWrite: true}}
	}
	input := flow.SaveQueryFilter{Name: "Same name", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}}
	red, blue := principal("00000000-0000-0000-0000-000000000001"), principal("00000000-0000-0000-0000-000000000002")
	a, err := api.saveFlowFilterDefinition(t.Context(), red, input)
	if err != nil {
		t.Fatal(err)
	}
	if store.actor != red.Email {
		t.Fatal("native filter audit lost authenticated actor")
	}
	b, err := api.saveFlowFilterDefinition(t.Context(), blue, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range []struct {
		p            *auth.Principal
		own, foreign flow.SavedQueryFilter
	}{{red, a, b}, {blue, b, a}} {
		page, err := api.listFlowFilters(t.Context(), lane.p, "", 100)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != lane.own.ID {
			t.Fatal("native list crossed tenant", err)
		}
		own, err := api.getFlowFilter(t.Context(), lane.p, lane.own.ID)
		if err != nil || own.ID != lane.own.ID {
			t.Fatal("native get lost owned filter", err)
		}
		foreign, err := api.getFlowFilter(t.Context(), lane.p, lane.foreign.ID)
		if err == nil || foreign.ID != "" {
			t.Fatal("native get leaked foreign filter")
		}
		update := input
		update.ID = lane.foreign.ID
		update.Version = 1
		if item, err := api.saveFlowFilterDefinition(t.Context(), lane.p, update); err == nil || item.ID != "" {
			t.Fatal("native update crossed tenant")
		}
		if err := api.deleteFlowFilter(t.Context(), lane.p, lane.foreign.ID, []string{"invalid"}); err == nil {
			t.Fatal("native delete crossed tenant")
		}
	}
	for _, p := range []*auth.Principal{nil, {UserID: "reader", Permissions: red.Permissions}, {TenantID: red.TenantID, Permissions: map[string]bool{permAIQuery: true}}, {TenantID: red.TenantID, Permissions: map[string]bool{permFlowRead: true}}} {
		before := store.calls
		if _, err := api.listFlowFilters(t.Context(), p, "", 100); err == nil {
			t.Fatal("native list missing authority")
		}
		if _, err := api.getFlowFilter(t.Context(), p, a.ID); err == nil {
			t.Fatal("native get missing authority")
		}
		if _, err := api.saveFlowFilterDefinition(t.Context(), p, input); err == nil {
			t.Fatal("native save missing authority")
		}
		if err := api.deleteFlowFilter(t.Context(), p, a.ID, []string{"1"}); err == nil {
			t.Fatal("native delete missing authority")
		}
		if store.calls != before {
			t.Fatal("native filter touched storage before tenant/source authorization")
		}
	}
	reader := principal(red.TenantID)
	delete(reader.Permissions, permFlowFiltersWrite)
	before := store.calls
	if _, err := api.saveFlowFilterDefinition(t.Context(), reader, input); err == nil {
		t.Fatal("native reader mutated filter")
	}
	if err := api.deleteFlowFilter(t.Context(), reader, a.ID, []string{"1"}); err == nil {
		t.Fatal("native reader deleted filter")
	}
	if store.calls != before {
		t.Fatal("native write permission checked after storage")
	}
	update := input
	update.ID = a.ID
	update.Version = 1
	next, err := api.saveFlowFilterDefinition(t.Context(), red, update)
	if err != nil || next.Version != 2 {
		t.Fatal("native optimistic update failed", err)
	}
	if _, err := api.saveFlowFilterDefinition(t.Context(), red, update); err == nil {
		t.Fatal("native stale version accepted")
	}
	if err := api.deleteFlowFilter(t.Context(), red, a.ID, []string{"1"}); err == nil {
		t.Fatal("native stale delete accepted")
	}
	if err := api.deleteFlowFilter(t.Context(), red, a.ID, []string{"2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.getFlowFilter(t.Context(), red, a.ID); err == nil {
		t.Fatal("native deleted filter remains visible")
	}
}

type nativeFlowViewContextService interface {
	listFlowViews(context.Context, *auth.Principal, flow.QueryViewList) (flow.QueryViewPage, error)
	getFlowViewByID(context.Context, *auth.Principal, string) (flow.SavedQueryView, error)
	saveFlowViewDefinition(context.Context, *auth.Principal, flow.SaveQueryView) (flow.SavedQueryView, error)
	deleteFlowView(context.Context, *auth.Principal, string, []string) error
	setFlowViewFavorite(context.Context, *auth.Principal, string, *bool) error
}
type observedNativeViews struct {
	flow.QueryViewStore
	calls int
}

func (s *observedNativeViews) GetQueryView(ctx context.Context, tenant, user, id string) (flow.SavedQueryView, error) {
	s.calls++
	return s.QueryViewStore.GetQueryView(ctx, tenant, user, id)
}
func (s *observedNativeViews) ListQueryViews(ctx context.Context, tenant, user string, input flow.QueryViewList) (flow.QueryViewPage, error) {
	s.calls++
	return s.QueryViewStore.ListQueryViews(ctx, tenant, user, input)
}
func (s *observedNativeViews) SaveQueryView(ctx context.Context, tenant, user string, input flow.SaveQueryView) (flow.SavedQueryView, error) {
	s.calls++
	return s.QueryViewStore.SaveQueryView(ctx, tenant, user, input)
}
func (s *observedNativeViews) DeleteQueryView(ctx context.Context, tenant, user, id, version string) error {
	s.calls++
	return s.QueryViewStore.DeleteQueryView(ctx, tenant, user, id, version)
}
func (s *observedNativeViews) SetQueryViewPreference(ctx context.Context, tenant, user, id string, favorite *bool, opened bool) error {
	s.calls++
	return s.QueryViewStore.SetQueryViewPreference(ctx, tenant, user, id, favorite, opened)
}

func TestNativeFlowViewContextServiceScopesBeforeStore(t *testing.T) {
	store := &observedNativeViews{QueryViewStore: flow.NewMemoryQueryViewStore(nil, 0)}
	server := testServer(fakePinger{}).WithFlowQueryViews(store)
	api, ok := any(server).(nativeFlowViewContextService)
	if !ok {
		t.Fatal("native saved-view context services unavailable")
	}
	principal := func(tenant, user string) *auth.Principal {
		return &auth.Principal{TenantID: tenant, UserID: user, Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permFlowViewsWrite: true}}
	}
	red, blue := principal("00000000-0000-0000-0000-000000000001", "alice"), principal("00000000-0000-0000-0000-000000000002", "alice")
	bob := principal(red.TenantID, "bob")
	input := flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Same name", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 401 * 24 * 3600}, Plan: flow.QueryPlan{GroupBy: []string{"protocol"}}, Display: &flow.QueryViewDisplay{TimeStyle: "horizon", HorizonScale: "lane"}}}
	a, err := api.saveFlowViewDefinition(t.Context(), red, input)
	if err != nil {
		t.Fatal(err)
	}
	b, err := api.saveFlowViewDefinition(t.Context(), blue, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range []struct {
		p            *auth.Principal
		own, foreign flow.SavedQueryView
	}{{red, a, b}, {blue, b, a}} {
		page, err := api.listFlowViews(t.Context(), lane.p, flow.QueryViewList{})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != lane.own.ID {
			t.Fatal("native view list crossed tenant", err)
		}
		own, err := api.getFlowViewByID(t.Context(), lane.p, lane.own.ID)
		if err != nil || own.ID != lane.own.ID || own.Definition.Display.HorizonScale != "lane" {
			t.Fatal("native view lost saved configuration", err)
		}
		if foreign, err := api.getFlowViewByID(t.Context(), lane.p, lane.foreign.ID); err == nil || foreign.ID != "" {
			t.Fatal("native view get leaked foreign definition")
		}
		update := input
		update.ID = lane.foreign.ID
		update.Version = "1"
		if value, err := api.saveFlowViewDefinition(t.Context(), lane.p, update); err == nil || value.ID != "" {
			t.Fatal("native view update crossed tenant")
		}
		if err := api.deleteFlowView(t.Context(), lane.p, lane.foreign.ID, []string{"invalid"}); err == nil {
			t.Fatal("native view delete crossed tenant")
		}
	}
	if _, err := api.getFlowViewByID(t.Context(), bob, a.ID); err == nil {
		t.Fatal("native view private owner boundary lost")
	}
	input.ID = a.ID
	input.Version = "1"
	input.Definition.Visibility = "tenant"
	a, err = api.saveFlowViewDefinition(t.Context(), red, input)
	if err != nil || a.Version != "2" {
		t.Fatal("native view sharing update failed", err)
	}
	if item, err := api.getFlowViewByID(t.Context(), bob, a.ID); err != nil || item.ID != a.ID {
		t.Fatal("native shared reader denied", err)
	}
	input.Version = a.Version
	if _, err := api.saveFlowViewDefinition(t.Context(), bob, input); err == nil {
		t.Fatal("native shared reader rewrote owner view")
	}
	if err := api.deleteFlowView(t.Context(), bob, a.ID, []string{a.Version}); err == nil {
		t.Fatal("native shared reader deleted owner view")
	}
	delete(bob.Permissions, permFlowViewsWrite)
	yes := true
	if err := api.setFlowViewFavorite(t.Context(), bob, a.ID, &yes); err != nil {
		t.Fatal("native personal favorite borrowed write permission", err)
	}
	favorites, err := api.listFlowViews(t.Context(), bob, flow.QueryViewList{Tab: "favorites"})
	if err != nil || len(favorites.Items) != 1 {
		t.Fatal("native favorite not visible to subject", err)
	}
	favorites, err = api.listFlowViews(t.Context(), red, flow.QueryViewList{Tab: "favorites"})
	if err != nil || len(favorites.Items) != 0 {
		t.Fatal("native preference crossed subject", err)
	}
	for _, p := range []*auth.Principal{nil, {UserID: "alice", Permissions: red.Permissions}, {TenantID: red.TenantID, Permissions: red.Permissions}, {TenantID: red.TenantID, UserID: "alice", Permissions: map[string]bool{permAIQuery: true}}, {TenantID: red.TenantID, UserID: "alice", Permissions: map[string]bool{permFlowRead: true}}} {
		before := store.calls
		if _, err := api.listFlowViews(t.Context(), p, flow.QueryViewList{}); err == nil {
			t.Fatal("native view list missing authority")
		}
		if _, err := api.getFlowViewByID(t.Context(), p, a.ID); err == nil {
			t.Fatal("native view get missing authority")
		}
		if _, err := api.saveFlowViewDefinition(t.Context(), p, input); err == nil {
			t.Fatal("native view save missing authority")
		}
		if err := api.deleteFlowView(t.Context(), p, a.ID, []string{a.Version}); err == nil {
			t.Fatal("native view delete missing authority")
		}
		if err := api.setFlowViewFavorite(t.Context(), p, a.ID, &yes); err == nil {
			t.Fatal("native view favorite missing authority")
		}
		if store.calls != before {
			t.Fatal("native view touched storage before tenant/user/source authority")
		}
	}
	input.Version = "1"
	if _, err := api.saveFlowViewDefinition(t.Context(), red, input); err == nil {
		t.Fatal("native stale saved-view revision accepted")
	}
	if err := api.deleteFlowView(t.Context(), red, a.ID, []string{"1"}); err == nil {
		t.Fatal("native stale saved-view delete accepted")
	}
	if err := api.deleteFlowView(t.Context(), red, a.ID, []string{a.Version}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFlowViewRunScopesAndPreservesExactPeriods(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Now().UTC().Add(-10 * time.Minute)
	before := at.Add(-time.Hour)
	data := flowstore.NewMemory()
	if err := data.Insert(t.Context(), []flowstore.Row{
		{TenantID: red, TS: at, Protocol: "RED_NATIVE_RUN", BytesScaled: 9007199254740993},
		{TenantID: blue, TS: at, Protocol: "BLUE_NATIVE_RUN", BytesScaled: 9007199254740994},
		{TenantID: red, TS: before, Protocol: "RED_NATIVE_RUN", BytesScaled: 4503599627370497},
		{TenantID: blue, TS: before, Protocol: "BLUE_NATIVE_RUN", BytesScaled: 4503599627370498},
	}); err != nil {
		t.Fatal(err)
	}
	views := &observedNativeViews{QueryViewStore: flow.NewMemoryQueryViewStore(nil, 0)}
	server := testServer(fakePinger{}).WithFlowStore(data).WithFlowQueryViews(views)
	for _, lane := range []struct{ tenant, protocol, foreign, current, previous string }{{red, "RED_NATIVE_RUN", "BLUE_NATIVE_RUN", "9007199254740993", "4503599627370497"}, {blue, "BLUE_NATIVE_RUN", "RED_NATIVE_RUN", "9007199254740994", "4503599627370498"}} {
		p := &auth.Principal{TenantID: lane.tenant, UserID: "alice", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permFlowViewsWrite: true}}
		definition := flow.QueryViewDefinition{Name: "Native run", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 3600}, Plan: flow.QueryPlan{GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
		saved, err := server.saveFlowViewDefinition(t.Context(), p, flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		// Execution is a read operation: it must not borrow shared configuration write rights.
		p.Permissions[permFlowViewsWrite] = false
		result, err := server.runFlowView(t.Context(), p, saved.ID)
		if err != nil || result.Query == nil || result.Comparison != nil || result.Query.Flow == nil || len(result.Query.Flow.Rows) != 1 || result.Query.Flow.Rows[0].Metrics["bytes:total"] != lane.current || result.Query.Flow.Rows[0].Group["protocol"] != lane.protocol {
			t.Fatal("native saved query changed source scope/precision", err)
		}
		p.Permissions[permFlowViewsWrite] = true
		saved.Definition.Comparison = &flow.QueryViewComparison{Mode: "absolute", From: before.Add(-time.Minute), To: before.Add(time.Minute)}
		saved, err = server.saveFlowViewDefinition(t.Context(), p, flow.SaveQueryView{ID: saved.ID, Version: saved.Version, Definition: saved.Definition})
		if err != nil {
			t.Fatal(err)
		}
		result, err = server.runFlowView(t.Context(), p, saved.ID)
		if err != nil || result.Query != nil || result.Comparison == nil || result.Comparison.Flow == nil || len(result.Comparison.Flow.Current.Rows) != 1 || len(result.Comparison.Flow.Previous.Rows) != 1 {
			t.Fatal("native saved comparison lost periods", err)
		}
		if result.Comparison.Flow.Current.Rows[0].Metrics["bytes:total"] != lane.current || result.Comparison.Flow.Previous.Rows[0].Metrics["bytes:total"] != lane.previous {
			t.Fatal("native comparison changed exact source counts")
		}
		encoded, err := json.Marshal(result.Comparison)
		if err != nil || strings.Contains(string(encoded), lane.foreign) || strings.Contains(string(encoded), lane.tenant) {
			t.Fatal("native comparison exposed foreign/private scope")
		}
		recents, err := server.listFlowViews(t.Context(), p, flow.QueryViewList{Tab: "recents"})
		if err != nil || len(recents.Items) != 1 || recents.Items[0].LastOpenedAt == nil {
			t.Fatal("native execution did not record scoped recency", err)
		}
		foreign := &auth.Principal{TenantID: map[string]string{red: blue, blue: red}[lane.tenant], UserID: p.UserID, Permissions: p.Permissions}
		if result, err := server.runFlowView(t.Context(), foreign, saved.ID); err == nil || result.Query != nil || result.Comparison != nil {
			t.Fatal("native saved run crossed tenant")
		}
		for _, missing := range []*auth.Principal{nil, {UserID: "alice", Permissions: p.Permissions}, {TenantID: lane.tenant, Permissions: p.Permissions}, {TenantID: lane.tenant, UserID: "alice", Permissions: map[string]bool{permAIQuery: true}}, {TenantID: lane.tenant, UserID: "alice", Permissions: map[string]bool{permFlowRead: true}}} {
			calls := views.calls
			if result, err := server.runFlowView(t.Context(), missing, saved.ID); err == nil || result.Query != nil || result.Comparison != nil {
				t.Fatal("native saved run missing authority")
			}
			if views.calls != calls {
				t.Fatal("native saved run read storage before principal authority")
			}
		}
	}
}
