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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNMSDiscoverySyncRouteKeepsTwoTenantsSeparate(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	type fixture struct {
		tenant, contextID, host, plan string
	}
	a := fixture{tenant: freshTenant(t, db, "rmm-alpha"), host: "alpha.lab"}
	b := fixture{tenant: freshTenant(t, db, "rmm-beta"), host: "beta.lab"}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.tenant, b.tenant}); err != nil {
			t.Error(err)
		}
	})
	for _, owner := range []*fixture{&a, &b} {
		got := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", owner.tenant,
			map[string]string{"site_label": "West", "vrf_label": "Private"})
		var routingContext entity.ContextRecord
		if got.Code != http.StatusCreated || json.Unmarshal(got.Body.Bytes(), &routingContext) != nil {
			t.Fatalf("create routing context: %d %s", got.Code, got.Body.String())
		}
		owner.contextID = routingContext.ContextID
	}
	start := func(owner, contextID string) *httptest.ResponseRecorder {
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/live-plans", owner,
			map[string]string{"context_id": contextID, "instance_ref": "same-site", "source_kind": "rmm"})
	}
	checkAvailability := func(tenant string, want bool) {
		t.Helper()
		self := apiReq(t, h, http.MethodGet, "/v1/me", tenant, nil)
		var result struct {
			Available *bool `json:"rmm_inventory_sync"`
		}
		if self.Code != http.StatusOK || json.Unmarshal(self.Body.Bytes(), &result) != nil ||
			(want && (result.Available == nil || !*result.Available)) || (!want && result.Available != nil) {
			t.Fatalf("unexpected inventory availability for this tenant: HTTP %d, want %t", self.Code, want)
		}
	}
	checkAvailability(a.tenant, false)
	hidden := start(a.tenant, a.contextID)
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("disabled MSP seam was visible: %d %s", hidden.Code, hidden.Body.String())
	}
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	newNative := func() *mcp.Server {
		return NewMCPServerWithPolicyLoader(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
			db.Pool(), nil, 0, gate, nil, nil, nil, AISources{NativeFlow: srv})
	}
	principal := func(owner fixture, write bool) *auth.Principal {
		return &auth.Principal{TenantID: owner.tenant, UserID: "inventory-reviewer",
			Permissions: map[string]bool{permNMSImportRead: true, permNMSImportWrite: write}}
	}
	const syncTool = "nms_import_inventory_sync"
	input := func(contextID string) mcp.NMSImportDiscoveryInput {
		return mcp.NMSImportDiscoveryInput{ContextID: contextID, InstanceRef: "same-site"}
	}
	if _, failed := nativeControlCall(t, newNative(), principal(a, true), syncTool, input(a.contextID)); !failed {
		t.Fatal("unconfigured native inventory sync was callable")
	}
	var calls int
	mapped := map[string]bool{a.tenant: true}
	srv.WithDiscoveryInventorySync(func(ctx context.Context, contextID, alias string, store nmsimport.CaptureStore) (nmsimport.DiscoveryPlan, error) {
		calls++
		tenant, _ := tenancy.FromContext(ctx)
		for _, owner := range []fixture{a, b} {
			if tenant.String() == owner.tenant && contextID == owner.contextID && alias == "same-site" {
				return store.PublishDiscovery(ctx, contextID, alias,
					[]nmsimport.DiscoveryDevice{{ExternalID: "same-device", Hostname: owner.host}})
			}
		}
		return nmsimport.DiscoveryPlan{}, nmsimport.ErrPlanUnavailable
	}, func(tenant string) bool { return mapped[tenant] })
	checkAvailability(a.tenant, true)
	checkAvailability(b.tenant, false)
	mapped[b.tenant] = true
	checkAvailability(b.tenant, true)
	native := newNative()
	for _, attempt := range []struct{ caller, sibling fixture }{{a, b}, {b, a}} {
		if response := start(attempt.caller.tenant, attempt.sibling.contextID); response.Code != http.StatusNotFound || calls != 0 {
			t.Fatalf("foreign context reached the source adapter: %d %s", response.Code, response.Body.String())
		}
		if _, failed := nativeControlCall(t, native, principal(attempt.caller, true), syncTool, input(attempt.sibling.contextID)); !failed || calls != 0 {
			t.Fatal("native sync admitted another tenant's routing context")
		}
		if _, failed := nativeControlCall(t, native, principal(attempt.caller, false), syncTool, input(attempt.caller.contextID)); !failed || calls != 0 {
			t.Fatal("native sync admitted a user without inventory write permission")
		}
	}
	for _, owner := range []*fixture{&a, &b} {
		response := start(owner.tenant, owner.contextID)
		var result struct {
			nmsimport.DiscoveryPlan
			State string `json:"state"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
			result.State != "sealed" || result.ContextID != owner.contextID || result.RowCount != 1 || result.PlanID == "" {
			t.Fatalf("owned site did not seal: %d %s", response.Code, response.Body.String())
		}
		owner.plan = result.PlanID
		rows := apiReq(t, h, http.MethodGet, "/v1/nms-imports/"+owner.plan+"/rows?context_id="+owner.contextID, owner.tenant, nil)
		var page nmsimport.SealedRowsPage
		if rows.Code != http.StatusOK || json.Unmarshal(rows.Body.Bytes(), &page) != nil ||
			len(page.Items) != 1 || page.Items[0].Hostname != owner.host || page.Items[0].Reviewed || page.RequiresSourceVerification {
			t.Fatalf("owned review plan: %d %s", rows.Code, rows.Body.String())
		}
		operator := principal(*owner, true)
		data, failed := nativeControlCall(t, native, operator, syncTool, input(owner.contextID))
		var sealed mcp.NMSImportDiscoveryResult
		if failed || json.Unmarshal(data, &sealed) != nil || sealed.State != "sealed" ||
			string(sealed.ContextID) != owner.contextID || sealed.PlanID == "" || len(sealed.SnapshotHash) != 64 || sealed.RowCount != 1 {
			t.Fatalf("native sync failed to seal the owned site: %s", data)
		}
		rowsData, failed := nativeControlCall(t, native, operator, "nms_import_rows",
			mcp.NMSImportRowsInput{ContextID: owner.contextID, PlanID: string(sealed.PlanID)})
		var nativeRows mcp.NMSImportRowsResult
		if failed || json.Unmarshal(rowsData, &nativeRows) != nil || len(nativeRows.Items) != 1 ||
			nativeRows.Items[0].Hostname != owner.host || nativeRows.Items[0].Reviewed {
			t.Fatalf("native sync did not publish the owned inert row: %s", rowsData)
		}
	}
	if calls != 4 {
		t.Fatalf("dispatcher ran %d times, want 4 owned calls", calls)
	}
	for _, attempt := range []struct{ caller, foreign fixture }{{a, b}, {b, a}} {
		response := apiReq(t, h, http.MethodGet, "/v1/nms-imports/"+attempt.foreign.plan+"/rows?context_id="+attempt.caller.contextID,
			attempt.caller.tenant, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("foreign plan visible: %d %s", response.Code, response.Body.String())
		}
		if _, failed := nativeControlCall(t, native, principal(attempt.caller, true), "nms_import_rows",
			mcp.NMSImportRowsInput{ContextID: attempt.caller.contextID, PlanID: attempt.foreign.plan}); !failed {
			t.Fatal("native MCP read a sibling review plan")
		}
	}
}
