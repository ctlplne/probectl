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

// Real PostgreSQL ownership/RLS/policy and encrypted shared snapshots, with an
// in-memory flow source. Actual ClickHouse execution has its separate proof;
// neither component substitutes for the release-binary/four-store receipt.
func TestExplorerRelatedTagsUseCurrentOwnedSubjectsAndReadGrants(t *testing.T) {
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
	sealer, err := tenantcrypto.NewEnvelopeSealer("related-tag-fixture", base64.StdEncoding.EncodeToString(key))
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
	for _, tenant := range []string{f.a, f.b} {
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			for _, kind := range []string{"exporter", "device", "agent"} {
				input := f.input(tenant, kind)
				if _, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{
					Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: f.tagID,
					TargetKind: kind, TargetID: input.TargetID, ExporterAgentID: input.ExporterAgentID,
					ExporterSourceRef: input.ExporterSourceRef, Value: kind + "-" + tenant,
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := rows.Insert(t.Context(), []flowstore.Row{
		{TenantID: f.a, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.b], BytesScaled: 100},
		{TenantID: f.a, TS: at, Exporter: "192.0.2.11", AgentID: f.agents[f.a], BytesScaled: 200},
		{TenantID: f.b, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.a], BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute),
		GroupBy: []string{"tag.role", "tag.device.role", "tag.agent.role"},
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
			t.Fatalf("related subject query: %d %s", response.Code, response.Body.String())
		}
		return out
	}
	check := func(tenant, hidden, total, matched string) {
		t.Helper()
		result := read(tenant, plan).Flow
		if result.Totals["bytes:total"] != total {
			t.Fatalf("related metadata changed raw totals: %+v", result)
		}
		found := false
		for _, row := range result.Rows {
			if row.Metrics["bytes:total"] != matched {
				continue
			}
			found = true
			for field, kind := range map[string]string{"tag.role": "exporter", "tag.device.role": "device", "tag.agent.role": "agent"} {
				want := kind + "-" + tenant
				if kind == hidden {
					want = ""
				}
				if row.Group[field] != want {
					t.Fatalf("%s selected foreign/raw-sender %s metadata: %+v", tenant, field, row)
				}
			}
		}
		if !found {
			t.Fatal("related metadata lost the selected exporter group")
		}
	}
	check(f.a, "", "300", "100")
	check(f.b, "", "900", "900")
	p := &auth.Principal{TenantID: f.a, UserID: "dev", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permTagsRead: true, "metrics.read": true, "agent.read": true}}
	backend := nativeMCPFlowBackend{srv}
	native, err := backend.FlowQuery(t.Context(), p, plan)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(native)
	if err != nil || !strings.Contains(string(encoded), `"value":"device-`+f.a+`"`) || strings.Contains(string(encoded), f.b) {
		t.Fatal("native MCP lost or crossed qualified subject values")
	}
	for _, permission := range []string{permTagsRead, permFlowRead, "metrics.read", "agent.read"} {
		if response := request(f.a, permission, plan); response.Code != http.StatusForbidden {
			t.Fatalf("missing %s returned %d", permission, response.Code)
		}
		delete(p.Permissions, permission)
		if _, err := backend.FlowQuery(t.Context(), p, plan); err == nil {
			t.Fatalf("MCP ignored missing %s", permission)
		}
		p.Permissions[permission] = true
	}
	// A direct exporter field must not hide the related grant needed by a
	// nested saved filter. Reuse one definition ID without collapsing names.
	filterResponse := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-filters", f.a, map[string]any{
		"name": "Agent role", "expression": map[string]any{"conditions": []map[string]any{{"field": "tag.agent.role", "op": "eq", "values": []string{"agent-" + f.a}}}},
	})
	var filter flow.SavedQueryFilter
	if filterResponse.Code != http.StatusCreated || json.Unmarshal(filterResponse.Body.Bytes(), &filter) != nil {
		t.Fatal("save qualified filter failed")
	}
	filtered := plan
	filtered.GroupBy = []string{"tag.role"}
	filtered.Filter = &flow.QueryFilterGroup{Groups: []flow.QueryFilterGroup{{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}}}
	if out := read(f.a, filtered); out.Flow.Totals["bytes:total"] != "100" {
		t.Fatal("nested related filter lost current association")
	}
	if response := request(f.a, "agent.read", filtered); response.Code != http.StatusForbidden {
		t.Fatal("nested saved related field bypassed source grant")
	}
	viewResponse := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-views", f.a, map[string]any{
		"definition": flow.QueryViewDefinition{Name: "Related roles", Plan: plan, Time: flow.QueryViewTime{Mode: "absolute"}},
	})
	var view flow.SavedQueryView
	if viewResponse.Code != http.StatusCreated || json.Unmarshal(viewResponse.Body.Bytes(), &view) != nil {
		t.Fatal("save qualified view failed")
	}
	for _, name := range plan.GroupBy {
		if view.Definition.TagIDs[name] != f.tagID {
			t.Fatalf("saved field %s lost immutable identity", name)
		}
	}
	if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-views/"+view.ID, f.b, nil); response.Code != http.StatusNotFound {
		t.Fatal("foreign tenant read qualified view")
	}
	if execution, err := backend.RunFlowView(t.Context(), p, view.ID); err != nil || execution.Query == nil {
		t.Fatalf("saved qualified view failed: %v", err)
	}
	paged := plan
	paged.PageSize = 1
	frozen := read(f.a, paged)
	if frozen.FlowPaging == nil || !frozen.FlowPaging.More {
		t.Fatal("qualified query did not create shared continuation")
	}
	comparison, err := backend.FlowCompare(t.Context(), p, mcp.NativeFlowCompareInput{Plan: paged, PreviousFrom: at.Add(-2 * time.Hour), PreviousTo: at.Add(-time.Hour)})
	if err != nil || comparison.Paging == nil || !comparison.Paging.More {
		t.Fatalf("qualified comparison continuation failed: %v", err)
	}
	for _, subject := range []struct{ kind, permission string }{{"device", "metrics.read"}, {"agent", "agent.read"}} {
		var policy *auth.Policy
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "withhold related metadata", Enabled: true, Effect: auth.PolicyDeny, Permission: subject.permission, Resource: map[string]string{"context_id": f.contextID}, Priority: 100})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(f.a)
		check(f.a, subject.kind, "300", "100")
		check(f.b, "", "900", "900")
		if response := request(f.a, "", flow.QueryPlan{Cursor: frozen.FlowPaging.NextCursor}); response.Code != http.StatusForbidden {
			t.Fatal("current related deny exposed frozen REST page")
		}
		if _, err := backend.FlowPage(t.Context(), p, frozen.FlowPaging.NextCursor); err == nil {
			t.Fatal("current related deny exposed frozen MCP page")
		}
		if _, err := backend.FlowComparisonPage(t.Context(), p, comparison.Paging.NextCursor); err == nil {
			t.Fatal("current related deny exposed comparison page")
		}
		for _, id := range []string{frozen.FlowPaging.SnapshotID, comparison.Paging.SnapshotID} {
			if response := apiReq(t, srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", f.a, nil); response.Code != http.StatusForbidden {
				t.Fatal("current related deny exposed CSV")
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.ABACPolicies{}).Delete(ctx, sc, policy.ID)
		}); err != nil {
			t.Fatal(err)
		}
		srv.abac.invalidate(f.a)
	}
	// Current registered identity is required even for a manual agent value.
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE agent_identities SET revoked_at=now() WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3`, f.a, f.agents[f.a], crypto.AgentSPIFFEID(f.a, f.agents[f.a])); err != nil {
		t.Fatal(err)
	}
	check(f.a, "agent", "300", "100")
	check(f.b, "", "900", "900")
	if response := apiReq(t, srv.Handler(), http.MethodPut, "/v1/tags/"+f.tagID, f.a, map[string]any{"key": "role_new"}); response.Code != http.StatusOK {
		t.Fatal("rename qualified tag definition failed")
	}
	if response := apiReq(t, srv.Handler(), http.MethodPost, "/v1/explorer/flow-views/"+view.ID+"/query", f.a, nil); response.Code != http.StatusConflict {
		t.Fatal("renamed qualified field silently retargeted a saved view")
	}
}
