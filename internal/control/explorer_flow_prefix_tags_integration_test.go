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

// Real tenant RLS/current source policy and encrypted shared snapshots; flow
// rows are explicit component fixtures, not a release/bus receipt.
func TestExplorerPrefixTagsUseOwnedNetworksAndCurrentReadGrants(t *testing.T) {
	f := newTagImportSubjectFixture(t)
	srv := f.srv
	srv.WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.db.Pool(), 0, audit.TenantRecord)).
		WithFlowQueryViews(flow.NewPostgresQueryViewStore(f.db.Pool(), 0, audit.TenantRecord))
	rows := &snapshotAPISource{Memory: flowstore.NewMemory()}
	srv.WithFlowStore(rows)
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("prefix-tag-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(f.db.Pool(), rows, objects, nil, nil, "test fixture has no backups", nil)
	srv.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: f.db.Pool(), Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(f.db.Pool()), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})
	childID := uuid(t)
	for _, tenant := range []string{f.a, f.b} {
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{
				Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: f.tagID,
				TargetKind: "prefix", TargetID: f.prefix, Value: "prefix-" + tenant,
			}); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,network_prefix)
			 VALUES ($1,$2,$3,'prefix','unannotated-child','192.0.2.128/25'::cidr)`, tenant, f.contextID, childID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := rows.Insert(t.Context(), []flowstore.Row{
		{TenantID: f.a, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.b], SrcAddr: "192.0.2.20", DstAddr: "192.0.2.200", BytesScaled: 100},
		{TenantID: f.a, TS: at, Exporter: "192.0.2.11", AgentID: f.agents[f.a], SrcAddr: "192.0.2.20", DstAddr: "192.0.2.200", BytesScaled: 200},
		{TenantID: f.b, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.a], SrcAddr: "192.0.2.20", DstAddr: "192.0.2.200", BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table",
		GroupBy: []string{"tag.src_prefix.role", "tag.dst_prefix.role"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	request := func(tenant, withheld string, selected flow.QueryPlan) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &selected})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/explorer/query", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		if withheld != "" {
			req.Header.Set(testWithholdPermissionsHeader, withheld)
		}
		out := httptest.NewRecorder()
		srv.Handler().ServeHTTP(out, req)
		return out
	}
	read := func(tenant string, selected flow.QueryPlan) explorerResult {
		t.Helper()
		response := request(tenant, "", selected)
		var out explorerResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &out) != nil || out.Flow == nil {
			t.Fatalf("prefix subject query failed: status %d", response.Code)
		}
		return out
	}
	check := func(tenant string, visible bool, total, matched string) {
		t.Helper()
		result := read(tenant, plan).Flow
		if result.Totals["bytes:total"] != total {
			t.Fatal("prefix metadata changed exact tenant total")
		}
		found := false
		for _, row := range result.Rows {
			want := ""
			if visible && row.Metrics["bytes:total"] == matched {
				want, found = "prefix-"+tenant, true
			}
			if row.Group["tag.src_prefix.role"] != want || row.Group["tag.dst_prefix.role"] != "" {
				t.Fatal("prefix selected foreign/unowned context or inherited through empty child")
			}
		}
		if visible && !found {
			t.Fatal("owned explicit prefix lost its row")
		}
	}
	check(f.a, true, "300", "100")
	check(f.b, true, "900", "900")
	p := &auth.Principal{TenantID: f.a, UserID: "dev", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permTagsRead: true, "entities.read": true}}
	backend := nativeMCPFlowBackend{srv}
	for _, tenant := range []string{f.a, f.b} {
		for _, withheld := range []string{"", "entities.read", permTagsRead} {
			req := httptest.NewRequest(http.MethodGet, "/v1/explorer/schema", nil)
			req.Header.Set("X-Probectl-Tenant", tenant)
			if withheld != "" {
				req.Header.Set(testWithholdPermissionsHeader, withheld)
			}
			out := httptest.NewRecorder()
			srv.Handler().ServeHTTP(out, req)
			if out.Code != http.StatusOK {
				t.Fatalf("prefix schema failed: %d", out.Code)
			}
			var schema struct {
				Flow struct {
					Fields []flow.QueryField `json:"fields"`
				} `json:"flow"`
			}
			if json.Unmarshal(out.Body.Bytes(), &schema) != nil {
				t.Fatal("REST prefix schema returned invalid JSON")
			}
			for _, selected := range plan.GroupBy {
				found := false
				for _, field := range schema.Flow.Fields {
					if field.Name == selected {
						found = true
						if field.Permission != "entities.read" {
							t.Fatal("REST prefix schema lost source permission")
						}
					}
				}
				if found != (withheld != permTagsRead) {
					t.Fatal("REST schema ignored tag discovery grant")
				}
			}
		}
	}
	// Discovery describes the tenant's tag vocabulary and extra query grant;
	// it reads no prefix facts. Execution below still requires entities.read.
	for _, withheld := range []string{"", "entities.read", permTagsRead} {
		if withheld != "" {
			delete(p.Permissions, withheld)
		}
		schema, err := backend.FlowSchema(t.Context(), p)
		if err != nil {
			t.Fatalf("native prefix schema failed: %v", err)
		}
		for _, selected := range plan.GroupBy {
			found := false
			for _, field := range schema.Fields {
				if field.Name == selected {
					found = true
					if field.Permission != "entities.read" {
						t.Fatal("prefix schema lost source permission")
					}
				}
			}
			if found != (withheld != permTagsRead) {
				t.Fatal("native schema ignored tag discovery grant")
			}
		}
		if withheld != "" {
			p.Permissions[withheld] = true
		}
	}
	native, err := backend.FlowQuery(t.Context(), p, plan)
	if err != nil {
		t.Fatalf("authorized native prefix query failed: %v", err)
	}
	encoded, err := json.Marshal(native)
	if err != nil || !strings.Contains(string(encoded), `"value":"prefix-`+f.a+`"`) || strings.Contains(string(encoded), f.b) {
		t.Fatal("native prefix output lost tenant ownership")
	}
	var identity struct {
		Flow struct {
			Tenant   string `json:"tag_tenant_id"`
			Revision string `json:"tag_revision"`
			IDs      []struct {
				Field string `json:"field"`
				ID    string `json:"id"`
			} `json:"tag_ids"`
		} `json:"flow"`
	}
	if json.Unmarshal(encoded, &identity) != nil || identity.Flow.Tenant != f.a || identity.Flow.Revision == "" {
		t.Fatal("native prefix output lost exact tenant/revision")
	}
	ids := map[string]string{}
	for _, field := range identity.Flow.IDs {
		ids[field.Field] = field.ID
	}
	for _, field := range plan.GroupBy {
		if ids[field] != f.tagID {
			t.Fatal("native prefix sides lost immutable definition identity")
		}
	}
	for _, permission := range []string{permAIQuery, permFlowRead, permTagsRead, "entities.read"} {
		if response := request(f.a, permission, plan); response.Code != http.StatusForbidden {
			t.Fatalf("missing prefix grant %s returned %d", permission, response.Code)
		}
		delete(p.Permissions, permission)
		if _, err := backend.FlowQuery(t.Context(), p, plan); err == nil {
			t.Fatal("native prefix query bypassed current global read grant")
		}
		p.Permissions[permission] = true
	}
	filterResponse := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-filters", f.a, map[string]any{
		"name": "Prefix role", "expression": map[string]any{"conditions": []map[string]any{{"field": "tag.src_prefix.role", "op": "eq", "values": []string{"prefix-" + f.a}}}},
	})
	var filter flow.SavedQueryFilter
	if filterResponse.Code != http.StatusCreated || json.Unmarshal(filterResponse.Body.Bytes(), &filter) != nil {
		t.Fatal("save prefix filter failed")
	}
	filtered := plan
	filtered.GroupBy = []string{"protocol"}
	filtered.Filter = &flow.QueryFilterGroup{Groups: []flow.QueryFilterGroup{{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}}}
	if result := read(f.a, filtered); result.Flow.Totals["bytes:total"] != "100" {
		t.Fatal("nested saved prefix filter lost current owned association")
	}
	if response := request(f.a, "entities.read", filtered); response.Code != http.StatusForbidden {
		t.Fatal("nested saved prefix filter bypassed source read grant")
	}
	viewResponse := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-views", f.a, map[string]any{
		"definition": flow.QueryViewDefinition{Name: "Prefix roles", Plan: plan, Time: flow.QueryViewTime{Mode: "absolute"}},
	})
	var view flow.SavedQueryView
	if viewResponse.Code != http.StatusCreated || json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil {
		t.Fatal("save prefix view failed")
	}
	for _, field := range plan.GroupBy {
		if view.Definition.TagIDs[field] != f.tagID {
			t.Fatal("saved prefix sides lost immutable tag identity")
		}
	}
	if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-views/"+view.ID, f.b, nil); response.Code != http.StatusNotFound {
		t.Fatal("foreign tenant read prefix view")
	}
	if _, err := backend.RunFlowView(t.Context(), p, view.ID); err != nil {
		t.Fatalf("native saved prefix view failed: %v", err)
	}
	paged := plan
	paged.PageSize = 1
	frozen := read(f.a, paged)
	if frozen.FlowPaging == nil || !frozen.FlowPaging.More {
		t.Fatal("prefix query did not create shared continuation")
	}
	comparison, err := backend.FlowCompare(t.Context(), p, mcp.NativeFlowCompareInput{Plan: paged, PreviousFrom: at.Add(-2 * time.Hour), PreviousTo: at.Add(-time.Hour)})
	if err != nil || comparison.Paging == nil || !comparison.Paging.More {
		t.Fatalf("prefix comparison continuation failed: %v", err)
	}
	var policy *auth.Policy
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "withhold prefix metadata", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"context_id": f.contextID}, Priority: 100})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	srv.abac.invalidate(f.a)
	check(f.a, false, "300", "")
	check(f.b, true, "900", "900")
	if response := request(f.a, "", flow.QueryPlan{Cursor: frozen.FlowPaging.NextCursor}); response.Code != http.StatusForbidden {
		t.Fatal("current prefix deny exposed frozen REST page")
	}
	if _, err := backend.FlowPage(t.Context(), p, frozen.FlowPaging.NextCursor); err == nil {
		t.Fatal("current prefix deny exposed frozen native page")
	}
	if _, err := backend.FlowComparisonPage(t.Context(), p, comparison.Paging.NextCursor); err == nil {
		t.Fatal("current prefix deny exposed comparison page")
	}
	for _, id := range []string{frozen.FlowPaging.SnapshotID, comparison.Paging.SnapshotID} {
		if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", f.a, nil); response.Code != http.StatusForbidden {
			t.Fatal("current prefix deny exposed CSV")
		}
	}
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, policy.ID)
	}); err != nil {
		t.Fatal(err)
	}
	srv.abac.invalidate(f.a)
	for _, network := range []string{"203.0.113.0/24", ""} {
		if response := apiReq(t, srv.Handler(), http.MethodPut, "/v1/entities/"+f.prefix+"/network-prefix", f.a, map[string]any{"context_id": f.contextID, "network_prefix": network}); response.Code != http.StatusOK {
			t.Fatalf("owned prefix range edit failed: %d", response.Code)
		}
		check(f.a, false, "300", "")
		check(f.b, true, "900", "900")
		if _, err := backend.FlowPage(t.Context(), p, frozen.FlowPaging.NextCursor); err != nil {
			t.Fatalf("range edit changed frozen native values: %v", err)
		}
		if _, err := backend.FlowComparisonPage(t.Context(), p, comparison.Paging.NextCursor); err != nil {
			t.Fatalf("range edit changed frozen comparison: %v", err)
		}
		for _, id := range []string{frozen.FlowPaging.SnapshotID, comparison.Paging.SnapshotID} {
			if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", f.a, nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "tag.src_prefix.role") || !strings.Contains(response.Body.String(), "prefix-"+f.a) || strings.Contains(response.Body.String(), f.b) {
				t.Fatal("range edit lost original CSV values or ownership")
			}
			if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", f.b, nil); response.Code != http.StatusNotFound {
				t.Fatal("foreign tenant read prefix snapshot CSV")
			}
		}
	}
}
