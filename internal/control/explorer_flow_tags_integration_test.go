// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestExplorerTagRuleRetagsHistoryAcrossTenantRESTBoundary(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "tag-explorer-a"), freshTenant(t, db, "tag-explorer-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove tag Explorer tenants: %v", err)
		}
	})
	rows := flowstore.NewMemory()
	srv.WithFlowStore(rows)
	ctx := t.Context()
	var redRulePath, redRuleID, redTagID string
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
}
