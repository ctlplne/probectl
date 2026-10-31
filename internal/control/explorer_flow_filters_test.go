// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func flowFilterCall(t *testing.T, srv *Server, tenant, method, path string, body any, withheld ...string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Probectl-Tenant", tenant)
	request.Header.Set(testWithholdPermissionsHeader, strings.Join(withheld, ","))
	return doReq(srv, request)
}

func TestExplorerFlowFilterRoutesPairedTenantsAndVersions(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	const root = "/v1/explorer/flow-filters"
	srv := testServer(fakePinger{})
	expression := flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}
	create := func(tenant, name string) flow.SavedQueryFilter {
		t.Helper()
		rec := flowFilterCall(t, srv, tenant, http.MethodPost, root, saveFlowFilterRequest{Name: name, Expression: expression})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create=%d %s", rec.Code, rec.Body.String())
		}
		var item flow.SavedQueryFilter
		if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		if item.ID == "" || item.Version != 1 || rec.Header().Get("Location") != root+"/"+item.ID || strings.Contains(rec.Body.String(), tenant) {
			t.Fatalf("invalid created filter: %s", rec.Body.String())
		}
		return item
	}
	a := create(red, "RED-ONLY")
	b := create(blue, "BLUE-ONLY")
	a2 := create(red, "RED-SECOND")
	for _, lane := range []struct{ tenant, own, foreign string }{{red, a.ID, b.ID}, {blue, b.ID, a.ID}} {
		list := flowFilterCall(t, srv, lane.tenant, http.MethodGet, root, nil)
		if list.Code != 200 || !strings.Contains(list.Body.String(), lane.own) || strings.Contains(list.Body.String(), lane.foreign) {
			t.Fatalf("list isolation: %d %s", list.Code, list.Body.String())
		}
		own := flowFilterCall(t, srv, lane.tenant, http.MethodGet, root+"/"+lane.own, nil)
		if own.Code != 200 || !strings.Contains(own.Body.String(), lane.own) {
			t.Fatalf("get own: %d %s", own.Code, own.Body.String())
		}
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			var body any
			if method == http.MethodPut {
				body = saveFlowFilterRequest{Name: "FOREIGN-UPDATE", Expression: expression, Version: 1}
			}
			rec := flowFilterCall(t, srv, lane.tenant, method, root+"/"+lane.foreign+"?version=1", body)
			missing := flowFilterCall(t, srv, lane.tenant, method, root+"/00000000-0000-0000-0000-000000000099?version=1", body)
			if rec.Code != 404 || missing.Code != 404 || strings.Contains(rec.Body.String(), lane.foreign) || strings.Contains(missing.Body.String(), "000000000099") {
				t.Fatalf("foreign/missing %s differ: %d/%d %s/%s", method, rec.Code, missing.Code, rec.Body.String(), missing.Body.String())
			}
		}
	}
	page := flowFilterCall(t, srv, red, http.MethodGet, root+"?limit=1", nil)
	var first flow.QueryFilterPage
	if err := json.Unmarshal(page.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if page.Code != 200 || len(first.Items) != 1 || first.Next == "" {
		t.Fatalf("first page=%s", page.Body.String())
	}
	next := flowFilterCall(t, srv, red, http.MethodGet, root+"?limit=1&after="+first.Next, nil)
	var second flow.QueryFilterPage
	if err := json.Unmarshal(next.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if next.Code != 200 || len(second.Items) != 1 || first.Items[0].ID == second.Items[0].ID || second.Next != "" {
		t.Fatalf("next page=%s", next.Body.String())
	}
	updated := flowFilterCall(t, srv, red, http.MethodPut, root+"/"+a.ID, saveFlowFilterRequest{Name: "RED-UPDATED", Expression: expression, Version: 1})
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), `"version":2`) {
		t.Fatalf("update=%d %s", updated.Code, updated.Body.String())
	}
	stale := flowFilterCall(t, srv, red, http.MethodPut, root+"/"+a.ID, saveFlowFilterRequest{Name: "STALE", Expression: expression, Version: 1})
	if stale.Code != 409 {
		t.Fatalf("stale update=%d %s", stale.Code, stale.Body.String())
	}
	stale = flowFilterCall(t, srv, red, http.MethodDelete, root+"/"+a.ID+"?version=1", nil)
	if stale.Code != 409 {
		t.Fatalf("stale delete=%d %s", stale.Code, stale.Body.String())
	}
	for _, item := range []struct {
		tenant, id string
		version    int64
	}{{red, a.ID, 2}, {red, a2.ID, 1}, {blue, b.ID, 1}} {
		deleted := flowFilterCall(t, srv, item.tenant, http.MethodDelete, root+"/"+item.id+"?version="+strconv.FormatInt(item.version, 10), nil)
		if deleted.Code != 204 {
			t.Fatalf("delete=%d %s", deleted.Code, deleted.Body.String())
		}
	}
}

func TestExplorerFlowFilterReferencesAuthorizeAndAffectQuery(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	const root = "/v1/explorer/flow-filters"
	filters := flow.NewMemoryQueryFilterStore(0)
	metric, err := filters.SaveQueryFilter(t.Context(), red, "op", flow.SaveQueryFilter{Name: "hidden metadata", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "in_if_name", Op: flow.QueryEqual, Values: []string{"private-interface"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	alias, err := filters.SaveQueryFilter(t.Context(), red, "op", flow.SaveQueryFilter{Name: "alias", Expression: flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: metric.ID}}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithFlowQueryFilters(filters)
	for _, path := range []string{root, root + "/" + alias.ID, root + "/" + metric.ID} {
		denied := flowFilterCall(t, srv, red, http.MethodGet, path, nil, permMetricsRead)
		if denied.Code != 403 || strings.Contains(denied.Body.String(), "private-interface") {
			t.Fatalf("hidden field read=%d %s", denied.Code, denied.Body.String())
		}
	}
	save := saveFlowFilterRequest{Name: "hidden through ref", Expression: flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: alias.ID}}}}
	denied := flowFilterCall(t, srv, red, http.MethodPost, root, save, permMetricsRead)
	if denied.Code != 403 {
		t.Fatalf("reference bypass=%d %s", denied.Code, denied.Body.String())
	}
	foreign := flowFilterCall(t, srv, blue, http.MethodPost, root, save)
	if foreign.Code != 404 || strings.Contains(foreign.Body.String(), metric.ID) {
		t.Fatalf("foreign ref=%d %s", foreign.Code, foreign.Body.String())
	}
	for _, permission := range []string{permAIQuery, permFlowRead, permFlowFiltersWrite} {
		denied = flowFilterCall(t, srv, red, http.MethodPost, root, save, permission)
		if denied.Code != 403 {
			t.Fatalf("missing %s allowed mutation: %d", permission, denied.Code)
		}
	}
	// Invalid or deleted dependencies must not make a shared filter impossible to repair/delete.
	if err := filters.DeleteQueryFilter(t.Context(), red, "op", metric.ID, 1); err != nil {
		t.Fatal(err)
	}
	repaired := flowFilterCall(t, srv, red, http.MethodPut, root+"/"+alias.ID, saveFlowFilterRequest{Name: "repaired", Version: 1, Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}})
	if repaired.Code != 200 {
		t.Fatalf("repair broken reference=%d %s", repaired.Code, repaired.Body.String())
	}
	at := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	records := flowstore.NewMemory()
	if err := records.Insert(t.Context(), []flowstore.Row{{TenantID: red, TS: at, Protocol: "tcp", DstPort: 443, BytesScaled: 10}, {TenantID: red, TS: at, Protocol: "udp", DstPort: 53, BytesScaled: 20}, {TenantID: blue, TS: at, Protocol: "FOREIGN", DstPort: 443, BytesScaled: 999}}); err != nil {
		t.Fatal(err)
	}
	srv.WithFlowStore(records)
	query := ai.ExplorerQuery{Question: "Saved port filter", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"protocol"}, Filter: &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: alias.ID}}}}}
	result := flowFilterCall(t, srv, red, http.MethodPost, "/v1/explorer/query", query)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `"tcp"`) || strings.Contains(result.Body.String(), `"udp"`) || strings.Contains(result.Body.String(), "FOREIGN") {
		t.Fatalf("query saved filter=%d %s", result.Code, result.Body.String())
	}
	var decoded explorerResult
	if err := json.Unmarshal(result.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Flow == nil || decoded.Flow.SavedFilterVersions[alias.ID] != 2 {
		t.Fatalf("missing resolved version: %s", result.Body.String())
	}
}

type failingFlowFilters struct{ flow.QueryFilterStore }

func (f failingFlowFilters) GetQueryFilter(context.Context, string, string) (flow.SavedQueryFilter, error) {
	return flow.SavedQueryFilter{}, errors.New("SECRET-SQL-AND-CREDENTIAL")
}
func TestExplorerFlowFiltersFailClosedWithoutLeakingStorageErrors(t *testing.T) {
	srv := testServer(fakePinger{}).WithFlowQueryFilters(failingFlowFilters{})
	response := flowFilterCall(t, srv, "00000000-0000-0000-0000-000000000001", http.MethodGet, "/v1/explorer/flow-filters/test", nil)
	if response.Code != 503 || strings.Contains(response.Body.String(), "SECRET") {
		t.Fatalf("storage error leak=%d %s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/explorer/flow-filters", nil)
	request = request.WithContext(auth.WithPrincipal(request.Context(), &auth.Principal{Permissions: map[string]bool{permAIQuery: true, permFlowRead: true}}))
	recorder := httptest.NewRecorder()
	apiHandler(srv.handleListFlowFilters).ServeHTTP(recorder, request)
	if recorder.Code != 401 {
		t.Fatalf("missing tenant=%d %s", recorder.Code, recorder.Body.String())
	}
}

type textVersionFlowFilters struct {
	flow.QueryFilterStore
	version int64
	seen    int64
}

func (store *textVersionFlowFilters) GetQueryFilter(_ context.Context, tenant, id string) (flow.SavedQueryFilter, error) {
	return flow.SavedQueryFilter{ID: id, TenantID: tenant, Version: store.version, VersionText: strconv.FormatInt(store.version, 10)}, nil
}
func (store *textVersionFlowFilters) SaveQueryFilter(_ context.Context, tenant, _ string, input flow.SaveQueryFilter) (flow.SavedQueryFilter, error) {
	store.seen = input.Version
	return flow.SavedQueryFilter{ID: input.ID, TenantID: tenant, Version: input.Version + 1, VersionText: strconv.FormatInt(input.Version+1, 10), Name: input.Name, Expression: input.Expression}, nil
}
func TestExplorerFlowFilterAcceptsExactTextRevisionAndRefusesConflicts(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-000000000001"
	store := &textVersionFlowFilters{QueryFilterStore: flow.NewMemoryQueryFilterStore(0), version: 9007199254740993}
	srv := testServer(fakePinger{}).WithFlowQueryFilters(store)
	body := map[string]any{"name": "exact", "version_text": "9007199254740993", "expression": map[string]any{"conditions": []any{map[string]any{"field": "dst_port", "op": "eq", "values": []string{"443"}}}}}
	response := flowFilterCall(t, srv, tenant, http.MethodPut, "/v1/explorer/flow-filters/exact", body)
	if response.Code != http.StatusOK || store.seen != 9007199254740993 || !strings.Contains(response.Body.String(), `"version_text":"9007199254740994"`) {
		t.Fatalf("text token rounded %d %d %s", response.Code, store.seen, response.Body.String())
	}
	body["version"] = 1
	if response := flowFilterCall(t, srv, tenant, http.MethodPut, "/v1/explorer/flow-filters/exact", body); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("conflicting versions accepted")
	}
}
