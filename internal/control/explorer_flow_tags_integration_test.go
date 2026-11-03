// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func TestExplorerTagRuleRetagsHistoryAcrossTenantRESTBoundary(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(db.Pool(), 0, audit.TenantRecord)).
		WithFlowQueryViews(flow.NewPostgresQueryViewStore(db.Pool(), 0, audit.TenantRecord))
	a, b := freshTenant(t, db, "tag-explorer-a"), freshTenant(t, db, "tag-explorer-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove tag Explorer tenants: %v", err)
		}
	})
	rows := &snapshotAPISource{Memory: flowstore.NewMemory()}
	srv.WithFlowStore(rows)
	// Exercise the shipping shared-snapshot path as well as query-time tags.
	// PG + encrypted temporary FS is a component proof, not release/four-store.
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("tag-snapshot-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(db.Pool(), rows, objects, nil, nil, "test fixture has no backups", nil)
	srv.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: db.Pool(), Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(db.Pool()), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})
	ctx := t.Context()
	var redRulePath, redRuleID, redTagID, redContextID string
	for _, item := range []struct{ tenant, agent, value string }{
		{a, "agent-tag-a", "blue"}, {b, "agent-tag-b", "red"},
	} {
		created := apiReq(t, srv.Handler(), http.MethodPost, "/v1/entity-contexts", item.tenant,
			map[string]any{"site_label": "site", "vrf_label": "vrf"})
		if created.Code != http.StatusCreated {
			t.Fatalf("create context: %d %s", created.Code, created.Body.String())
		}
		var contextRow struct {
			ContextID string `json:"context_id"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &contextRow); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			`INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,$2,'flow_exporter','192.0.2.10',$3)`,
		} {
			if _, err := db.Pool().Exec(ctx, statement, item.tenant, item.agent, contextRow.ContextID); err != nil {
				t.Fatal(err)
			}
		}
		created = apiReq(t, srv.Handler(), http.MethodPost, "/v1/tags", item.tenant,
			map[string]any{"key": "customer"})
		if created.Code != http.StatusCreated {
			t.Fatalf("create tag: %d %s", created.Code, created.Body.String())
		}
		var definition tags.Definition
		if err := json.Unmarshal(created.Body.Bytes(), &definition); err != nil {
			t.Fatal(err)
		}
		rulePath := "/v1/entity-contexts/" + contextRow.ContextID + "/tag-rules"
		ruleBody := map[string]any{"tag_id": definition.ID, "target_kind": "exporter",
			"match_kind": "cidr", "address_side": "exporter", "cidr": "192.0.2.0/24", "value": item.value}
		created = apiReq(t, srv.Handler(), http.MethodPost, rulePath, item.tenant, ruleBody)
		if created.Code != http.StatusCreated {
			t.Fatalf("create rule: %d %s", created.Code, created.Body.String())
		}
		if item.tenant == a {
			var rule tags.Rule
			if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil {
				t.Fatal(err)
			}
			// Save the exact tenant path and rule ID for the history edit below.
			redRulePath, redRuleID, redTagID = rulePath, rule.ID, definition.ID
			redContextID = contextRow.ContextID
		}
	}
	extra := apiReq(t, srv.Handler(), http.MethodPost, "/v1/tags", a,
		map[string]any{"key": "secret_a"})
	if extra.Code != http.StatusCreated {
		t.Fatalf("create tenant-only schema key: %d %s", extra.Code, extra.Body.String())
	}
	for _, tc := range []struct {
		tenant string
		want   bool
	}{{a, true}, {b, false}} {
		schema := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/schema", tc.tenant, nil)
		if schema.Code != http.StatusOK || strings.Contains(schema.Body.String(), `"tag.secret_a"`) != tc.want {
			t.Fatalf("tenant %s Explorer schema crossed tag scope: %d %s", tc.tenant, schema.Code, schema.Body.String())
		}
	}
	schemaRequest := httptest.NewRequest(http.MethodGet, "/v1/explorer/schema", nil)
	schemaRequest.Header.Set("X-Probectl-Tenant", a)
	schemaRequest.Header.Set(testWithholdPermissionsHeader, "tags.read")
	withheldSchema := httptest.NewRecorder()
	srv.Handler().ServeHTTP(withheldSchema, schemaRequest)
	if withheldSchema.Code != http.StatusOK || strings.Contains(withheldSchema.Body.String(), `"tag.customer"`) ||
		strings.Contains(withheldSchema.Body.String(), `"tag.secret_a"`) {
		t.Fatalf("schema exposed tag keys without tags.read: %d %s", withheldSchema.Code, withheldSchema.Body.String())
	}
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := rows.Insert(ctx, []flowstore.Row{
		{TenantID: a, TS: at, Exporter: "192.0.2.10", AgentID: "agent-tag-b", BytesScaled: 100},
		{TenantID: a, TS: at, Exporter: "192.0.2.11", BytesScaled: 200},
		{TenantID: b, TS: at, Exporter: "192.0.2.10", BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute),
		GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{
			Measure: "bytes", Calculation: "total", Role: "primary"}}}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Question: "Group by customer", Flow: &plan}
	var initialRevision int64
	read := func(tenant, withheld string) (*flowstore.PlanResult, int) {
		t.Helper()
		var response *httptest.ResponseRecorder
		if withheld == "" {
			response = apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", tenant, query)
		} else {
			body, err := json.Marshal(query)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Probectl-Tenant", tenant)
			req.Header.Set(testWithholdPermissionsHeader, withheld)
			response = httptest.NewRecorder()
			srv.Handler().ServeHTTP(response, req)
		}
		if response.Code != http.StatusOK {
			return nil, response.Code
		}
		var out explorerResult
		if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Flow, response.Code
	}
	for _, item := range []struct {
		tenant, named string
		bytes         string
	}{{a, "blue", "300"}, {b, "red", "900"}} {
		result, code := read(item.tenant, "")
		if code != http.StatusOK || result == nil || result.TagRevision < 1 || result.Totals["bytes:total"] != item.bytes {
			t.Fatalf("tenant %s flow query: status=%d result=%+v", item.tenant, code, result)
		}
		groups := map[string]string{}
		for _, row := range result.Rows {
			groups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
		}
		if item.tenant == a && (groups[item.named] != "100" || groups[""] != "200") ||
			item.tenant == b && (len(groups) != 1 || groups[item.named] != "900") {
			t.Fatalf("tenant %s selected foreign or untrusted agent tag: %+v", item.tenant, result.Rows)
		}
		if item.tenant == a {
			initialRevision = result.TagRevision
		}
	}
	if _, code := read(a, "tags.read"); code != http.StatusForbidden {
		t.Fatalf("withheld tags.read returned %d", code)
	}
	paged := query
	pagedPlan := *query.Flow
	pagedPlan.PageSize = 1
	paged.Flow = &pagedPlan
	frozenResponse := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", a, paged)
	var frozen explorerResult
	if frozenResponse.Code != http.StatusOK || json.Unmarshal(frozenResponse.Body.Bytes(), &frozen) != nil || frozen.FlowPaging == nil || !frozen.FlowPaging.More {
		t.Fatal("paired tag proof did not create a real shared result continuation")
	}
	resume := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: frozen.FlowPaging.NextCursor}}
	p := &auth.Principal{TenantID: a, UserID: "dev", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permTagsRead: true}}
	comparison, err := (nativeMCPFlowBackend{srv}).FlowCompare(ctx, p, mcp.NativeFlowCompareInput{Plan: pagedPlan, PreviousFrom: at.Add(-2 * time.Hour), PreviousTo: at.Add(-time.Hour)})
	if err != nil || comparison.Paging == nil || !comparison.Paging.More {
		t.Fatalf("tagged comparison did not create a shared continuation: %v", err)
	}
	savedFilter := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-filters", a,
		map[string]any{"name": "Customer blue", "expression": map[string]any{
			"conditions": []map[string]any{{"field": "tag.customer", "op": "eq", "values": []string{"blue"}}}}})
	if savedFilter.Code != http.StatusCreated {
		t.Fatalf("save tenant tag filter: %d %s", savedFilter.Code, savedFilter.Body.String())
	}
	var filterRow flow.SavedQueryFilter
	if err := json.Unmarshal(savedFilter.Body.Bytes(), &filterRow); err != nil {
		t.Fatal(err)
	}
	filteredPlan := plan
	filteredPlan.GroupBy = []string{"exporter"}
	filteredPlan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: filterRow.ID}}}
	filtered := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", a,
		ai.ExplorerQuery{Source: ai.ExplorerFlow, Question: "Use saved customer filter", Flow: &filteredPlan})
	if filtered.Code != http.StatusOK {
		t.Fatalf("saved tenant tag filter query: %d %s", filtered.Code, filtered.Body.String())
	}
	var filteredResult explorerResult
	if err := json.Unmarshal(filtered.Body.Bytes(), &filteredResult); err != nil {
		t.Fatal(err)
	}
	if filteredResult.Flow == nil || filteredResult.Flow.TagRevision != initialRevision ||
		filteredResult.Flow.Totals["bytes:total"] != "100" {
		t.Fatalf("saved tag filter lost tenant revision or selected wrong rows: %+v", filteredResult.Flow)
	}
	viewDefinition := flow.QueryViewDefinition{Name: "Customer history", Plan: plan,
		Time: flow.QueryViewTime{Mode: "absolute"}}
	viewCreated := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-views", a,
		map[string]any{"definition": viewDefinition})
	if viewCreated.Code != http.StatusCreated {
		t.Fatalf("save tenant tag view: %d %s", viewCreated.Code, viewCreated.Body.String())
	}
	var view flow.SavedQueryView
	if err := json.Unmarshal(viewCreated.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Definition.TagIDs["tag.customer"] != redTagID {
		t.Fatalf("saved view lost immutable tenant tag identity: %+v", view.Definition.TagIDs)
	}
	viewPath := "/v1/explorer/flow-views/" + view.ID
	if foreignView := apiReq(t, srv.Handler(), http.MethodGet, viewPath, b, nil); foreignView.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant read saved tag view: %d %s", foreignView.Code, foreignView.Body.String())
	}
	withheldViewRequest := httptest.NewRequest(http.MethodGet, viewPath, nil)
	withheldViewRequest.Header.Set("X-Probectl-Tenant", a)
	withheldViewRequest.Header.Set(testWithholdPermissionsHeader, "tags.read")
	withheldView := httptest.NewRecorder()
	srv.Handler().ServeHTTP(withheldView, withheldViewRequest)
	if withheldView.Code != http.StatusForbidden || strings.Contains(withheldView.Body.String(), "customer") {
		t.Fatalf("withheld tag permission exposed saved view: %d %s", withheldView.Code, withheldView.Body.String())
	}
	runView := func() *flowstore.PlanResult {
		t.Helper()
		response := apiReq(t, srv.Handler(), http.MethodPost, viewPath+"/query", a, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("run saved tag view: %d %s", response.Code, response.Body.String())
		}
		var result explorerResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Flow == nil {
			t.Fatalf("saved tag view returned no flow result: %s", response.Body.String())
		}
		return result.Flow
	}
	if result := runView(); result == nil || result.TagRevision != initialRevision ||
		result.Totals["bytes:total"] != "300" {
		t.Fatalf("saved tag view changed initial totals or revision: %+v", result)
	}
	changed := apiReq(t, srv.Handler(), http.MethodPut, redRulePath+"/"+redRuleID, a,
		map[string]any{"tag_id": redTagID, "target_kind": "exporter",
			"match_kind": "cidr", "address_side": "exporter", "cidr": "192.0.2.0/24", "value": "green"})
	if changed.Code != http.StatusOK {
		t.Fatalf("change tag rule: %d %s", changed.Code, changed.Body.String())
	}
	retagged, code := read(a, "")
	if code != http.StatusOK || retagged == nil || retagged.TagRevision <= initialRevision ||
		retagged.Totals["bytes:total"] != "300" {
		t.Fatalf("retagged history changed totals: status=%d result=%+v", code, retagged)
	}
	groups := map[string]string{}
	for _, row := range retagged.Rows {
		groups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
	}
	if groups["green"] != "100" || groups["blue"] != "" || groups[""] != "200" {
		t.Fatalf("current rule failed to retag retained history: %+v", groups)
	}
	viewResult := runView()
	viewGroups := map[string]string{}
	for _, row := range viewResult.Rows {
		viewGroups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
	}
	if viewResult.TagRevision != retagged.TagRevision ||
		viewResult.Totals["bytes:total"] != "300" ||
		viewGroups["green"] != "100" || viewGroups[""] != "200" || viewGroups["blue"] != "" {
		t.Fatalf("saved tag view did not use current rules for history: %+v", viewResult)
	}
	beforeResume := rows.queries.Load()
	frozenPage := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", a, resume)
	var frozenNext explorerResult
	if frozenPage.Code != http.StatusOK || json.Unmarshal(frozenPage.Body.Bytes(), &frozenNext) != nil || frozenNext.Flow == nil || frozenNext.Flow.TagRevision != initialRevision || rows.queries.Load() != beforeResume {
		t.Fatal("rule edits altered frozen values or reran event source execution")
	}
	frozenBlue := false
	for _, row := range append(append([]flowstore.PlanRow{}, frozen.Flow.Rows...), frozenNext.Flow.Rows...) {
		frozenBlue = frozenBlue || row.Group["tag.customer"] == "blue" && row.Metrics["bytes:total"] == "100"
	}
	if !frozenBlue {
		t.Fatal("frozen rows lost their original tag values")
	}
	if _, err := (nativeMCPFlowBackend{srv}).FlowPage(ctx, p, frozen.FlowPaging.NextCursor); err != nil {
		t.Fatalf("authorized user MCP page lost its current actor: %v", err)
	}
	if _, err := (nativeMCPFlowBackend{srv}).FlowComparisonPage(ctx, p, comparison.Paging.NextCursor); err != nil || rows.queries.Load() != beforeResume {
		t.Fatal("authorized comparison revalidation failed or reran the event query")
	}
	for _, permission := range []string{permTagsRead, permFlowRead} {
		var policy *auth.Policy
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "revoke frozen tag context", Enabled: true, Effect: auth.PolicyDeny, Permission: permission, Resource: map[string]string{"context_id": redContextID}, Priority: 100})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(a)
		fresh, code := read(a, "")
		if code != http.StatusOK || fresh == nil || fresh.Totals["bytes:total"] != "300" || len(fresh.Rows) != 1 || fresh.Rows[0].Group["tag.customer"] != "" {
			t.Fatal("fresh context policy changed raw totals or disclosed denied metadata")
		}
		if denied := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/query", a, resume); denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), `"blue"`) {
			t.Fatal("a current context deny exposed a frozen page")
		}
		if _, err := (nativeMCPFlowBackend{srv}).FlowPage(ctx, p, frozen.FlowPaging.NextCursor); err == nil {
			t.Fatal("user MCP bypassed frozen tag context revocation")
		}
		if _, err := (nativeMCPFlowBackend{srv}).FlowComparisonPage(ctx, p, comparison.Paging.NextCursor); err == nil {
			t.Fatal("comparison continuation bypassed tag context revocation")
		}
		for _, id := range []string{frozen.FlowPaging.SnapshotID, comparison.Paging.SnapshotID} {
			if denied := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", a, nil); denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), `"blue"`) {
				t.Fatal("CSV bypassed frozen tag context revocation")
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.ABACPolicies{}).Delete(ctx, sc, policy.ID)
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(a)
	}
	renamed := apiReq(t, srv.Handler(), http.MethodPut, "/v1/tags/"+redTagID, a,
		map[string]any{"key": "customer_new"})
	if renamed.Code != http.StatusOK {
		t.Fatalf("rename tenant tag: %d %s", renamed.Code, renamed.Body.String())
	}
	if stale := apiReq(t, srv.Handler(), http.MethodPost, viewPath+"/query", a, nil); stale.Code != http.StatusConflict {
		t.Fatalf("renamed tag retargeted saved view: %d %s", stale.Code, stale.Body.String())
	}
}
