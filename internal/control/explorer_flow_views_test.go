// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestExplorerFlowDisplayRejectsUnknownScopeWithoutMutation(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	const root = "/v1/explorer/flow-views"
	srv := testServer(fakePinger{})
	definition := flow.QueryViewDefinition{Name: "PRESERVE-OWNER-VIEW", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 60}, Plan: flow.QueryPlan{GroupBy: []string{"protocol"}}}
	if created := flowFilterCall(t, srv, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition}); created.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", created.Code, created.Body.String())
	}
	encoded, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	var injected map[string]any
	if err := json.Unmarshal(encoded, &injected); err != nil {
		t.Fatal(err)
	}
	injected["display"] = map[string]any{"tenant_id": blue, "total_overlay": true}
	rejected := flowFilterCall(t, srv, red, http.MethodPost, root, map[string]any{"definition": injected})
	if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), `"code":"bad_request"`) || strings.Contains(rejected.Body.String(), blue) {
		t.Fatalf("unknown scope was not strictly rejected: %d %s", rejected.Code, rejected.Body.String())
	}
	for tenant, count := range map[string]int{red: 1, blue: 0} {
		response := flowFilterCall(t, srv, tenant, http.MethodGet, root, nil)
		var page flow.QueryViewPage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != count {
			t.Fatal("invalid display changed a tenant's saved views")
		}
	}
}

func TestExplorerFlowViewsRoutesPreserveQueriesAndFailClosed(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	const root = "/v1/explorer/flow-views"
	srv := testServer(fakePinger{})
	filters := flow.NewMemoryQueryFilterStore(0)
	srv.WithFlowQueryFilters(filters)
	filter, err := filters.SaveQueryFilter(t.Context(), red, "qa", flow.SaveQueryFilter{Name: "named", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "protocol", Op: flow.QueryEqual, Values: []string{"ipfix"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := flow.QueryViewDefinition{Name: "RED-ONLY", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 401 * 24 * 3600}, Plan: flow.QueryPlan{GroupBy: []string{"src_addr"}, Filter: &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}}}
	created := flowFilterCall(t, srv, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition})
	if created.Code != http.StatusCreated {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var view flow.SavedQueryView
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Version != "1" || view.Definition.Visibility != "private" || strings.Contains(created.Body.String(), red) {
		t.Fatal("view version/scope/default invalid")
	}
	path := root + "/" + view.ID
	for _, test := range []struct {
		method, path string
		body         any
	}{{http.MethodGet, path, nil}, {http.MethodPut, path, saveFlowViewRequest{Version: view.Version, Definition: definition}}, {http.MethodDelete, path + "?version=1", nil}, {http.MethodPut, path + "/preferences", map[string]any{"favorite": true}}, {http.MethodPost, path + "/query", nil}} {
		response := flowFilterCall(t, srv, blue, test.method, test.path, test.body)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "RED-ONLY") {
			t.Fatalf("foreign route %s %s %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	response := flowFilterCall(t, srv, blue, http.MethodGet, root, nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), view.ID) {
		t.Fatal("foreign list leaked")
	}
	if response := flowFilterCall(t, srv, red, http.MethodPost, path+"/query", nil); response.Code != http.StatusOK {
		t.Fatalf("view run %d %s", response.Code, response.Body.String())
	}
	if response := flowFilterCall(t, srv, red, http.MethodPost, path+"/query", map[string]any{"source": "changes"}); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("execution accepted override")
	}
	if response := flowFilterCall(t, srv, red, http.MethodPut, path+"/preferences", map[string]any{"favorite": true}, permFlowViewsWrite); response.Code != http.StatusNoContent {
		t.Fatal("private preference borrowed shared configuration permission")
	}
	if response := flowFilterCall(t, srv, red, http.MethodGet, root+"?tab=favorites", nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), view.ID) {
		t.Fatal("favorite list missing")
	}
	if response := flowFilterCall(t, srv, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition}, permFlowViewsWrite); response.Code != http.StatusForbidden {
		t.Fatal("query reader acquired writes")
	}
	for _, route := range []string{path, path + "/query"} {
		method := http.MethodGet
		if strings.HasSuffix(route, "/query") {
			method = http.MethodPost
		}
		if response := flowFilterCall(t, srv, red, method, route, nil, permFlowRead); response.Code != http.StatusForbidden {
			t.Fatal("saved query bypassed source permission")
		}
	}
	definition.Visibility = "tenant"
	update := flowFilterCall(t, srv, red, http.MethodPut, path, saveFlowViewRequest{Version: "1", Definition: definition})
	if update.Code != http.StatusOK {
		t.Fatalf("update %d %s", update.Code, update.Body.String())
	}
	if stale := flowFilterCall(t, srv, red, http.MethodPut, path, saveFlowViewRequest{Version: "1", Definition: definition}); stale.Code != http.StatusConflict {
		t.Fatal("stale view update accepted")
	}
	joined := definition
	joined.Plan.GroupBy = []string{"in_if_name"}
	if response := flowFilterCall(t, srv, red, http.MethodPost, root, saveFlowViewRequest{Definition: joined}, permMetricsRead); response.Code != http.StatusForbidden {
		t.Fatal("saved plan omitted joined permission")
	}
	definition.Plan.Cursor = "transient-cursor"
	if response := flowFilterCall(t, srv, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition}); response.Code != http.StatusUnprocessableEntity {
		t.Fatal("transient cursor persisted in view")
	}
	if deleted := flowFilterCall(t, srv, red, http.MethodDelete, path+"?version=2", nil); deleted.Code != http.StatusNoContent {
		t.Fatal("delete failed")
	}
	if gone := flowFilterCall(t, srv, red, http.MethodGet, path, nil); gone.Code != http.StatusNotFound {
		t.Fatal("deleted view remained")
	}
}
