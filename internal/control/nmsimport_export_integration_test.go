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
	"net/url"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

func TestNMSImportExportPreviewRoutesKeepVendorPagesInOneTenant(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "nms-export-a"), freshTenant(t, db, "nms-export-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove NMS export tenants: %v", err)
		}
	})
	type fixture struct {
		tenant, contextID, planID, resource, raw, rowKind, sourceID string
	}
	makeFixture := func(tenant, sourceKind, resource, raw, rowKind, sourceID string) fixture {
		t.Helper()
		response := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": "West DC", "vrf_label": "Private"})
		var routing entity.ContextRecord
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &routing) != nil {
			t.Fatalf("create preview context: %d %s", response.Code, response.Body.String())
		}
		start := apiReq(t, h, http.MethodPost, "/v1/nms-imports/export-plans", tenant,
			map[string]string{"context_id": routing.ContextID, "source_kind": sourceKind,
				"instance_ref": "preview-lab"})
		var plan struct {
			PlanID  string `json:"plan_id"`
			State   string `json:"state"`
			Preview bool   `json:"preview"`
		}
		if start.Code != http.StatusCreated || json.Unmarshal(start.Body.Bytes(), &plan) != nil ||
			plan.PlanID == "" || plan.State != "capturing" || !plan.Preview {
			t.Fatalf("start preview plan: %d %s", start.Code, start.Body.String())
		}
		return fixture{tenant, routing.ContextID, plan.PlanID, resource, raw, rowKind, sourceID}
	}
	left := makeFixture(a, "orion", "nodes",
		`{"results":[{"NodeID":17,"Caption":"Edge R1","IPAddress":"10.42.0.1","Location":"West","PollInterval":120,"Community":"source-secret"}]}`,
		"device", "17")
	right := makeFixture(b, "prtg", "devices",
		`[{"id":"101","parentid":"20","name":"Edge R1","basic":{"host":"10.42.0.1","credentials":"source-secret"}}]`,
		"device", "101")
	if left.planID == right.planID || left.contextID == right.contextID {
		t.Fatal("preview plans or contexts collided across tenants")
	}
	pageURL := func(f fixture, contextID, planID string) string {
		return "/v1/nms-imports/" + planID + "/export-pages?context_id=" + url.QueryEscape(contextID) +
			"&page_number=0&first_row=0&resource=" + f.resource
	}
	sealBody := func(contextID string) map[string]any {
		return map[string]any{"context_id": contextID, "expected_pages": 1, "expected_rows": 1}
	}
	for _, own := range []fixture{left, right} {
		other := left
		if own.tenant == left.tenant {
			other = right
		}
		if response := apiReq(t, h, http.MethodPost,
			pageURL(own, own.contextID, other.planID), own.tenant,
			json.RawMessage(own.raw)); response.Code != http.StatusNotFound {
			t.Fatalf("foreign plan accepted source page: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/"+other.planID+"/export-seal", own.tenant,
			sealBody(own.contextID)); response.Code != http.StatusNotFound {
			t.Fatalf("foreign plan sealed: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost,
			pageURL(own, other.contextID, own.planID), own.tenant,
			json.RawMessage(own.raw)); response.Code != http.StatusNotFound {
			t.Fatalf("foreign context accepted source page: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost,
			pageURL(own, own.contextID, own.planID), own.tenant,
			json.RawMessage(own.raw)); response.Code != http.StatusOK ||
			!strings.Contains(response.Body.String(), `"page_hash"`) {
			t.Fatalf("capture own export page: %d %s", response.Code, response.Body.String())
		}
		seal := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/"+own.planID+"/export-seal", own.tenant,
			sealBody(own.contextID))
		var sealed struct {
			State        string `json:"state"`
			SnapshotHash string `json:"snapshot_hash"`
			Preview      bool   `json:"preview"`
		}
		if seal.Code != http.StatusOK || json.Unmarshal(seal.Body.Bytes(), &sealed) != nil ||
			sealed.State != "sealed" || len(sealed.SnapshotHash) != 64 || !sealed.Preview {
			t.Fatalf("seal own export preview: %d %s", seal.Code, seal.Body.String())
		}
		response := apiReq(t, h, http.MethodGet,
			"/v1/nms-imports/"+own.planID+"/rows?context_id="+own.contextID,
			own.tenant, nil)
		var rows nmsimport.SealedRowsPage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &rows) != nil ||
			len(rows.Items) != 1 || rows.Items[0].Kind != own.rowKind ||
			rows.Items[0].ExternalID != own.sourceID ||
			len(rows.Items[0].UnmappedCodes) == 0 ||
			strings.Contains(response.Body.String(), "source-secret") {
			t.Fatalf("unsafe or missing preview row: %d %s", response.Code, response.Body.String())
		}
	}
	if response := apiReq(t, h, http.MethodPost, "/v1/nms-imports/export-plans", a,
		map[string]string{"context_id": left.contextID, "source_kind": "librenms",
			"instance_ref": "preview-lab"}); response.Code != http.StatusBadRequest {
		t.Fatalf("live source entered export preview route: %d %s", response.Code, response.Body.String())
	}
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	mcpServer := NewMCPServerWithPolicyLoader(&config.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), db.Pool(), nil, 0,
		gate, nil, nil, nil)
	for _, own := range []fixture{left, right} {
		principal := &auth.Principal{TenantID: own.tenant, UserID: "import-writer",
			Permissions: map[string]bool{permNMSImportWrite: true, permNMSImportRead: true}}
		startData, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_export_start", mcp.NMSImportExportStartInput{
				ContextID: own.contextID, SourceKind: map[string]string{
					"nodes": "orion", "devices": "prtg"}[own.resource], InstanceRef: "mcp-lab"})
		var started mcp.NMSImportExportStartResult
		if failed || json.Unmarshal(startData, &started) != nil ||
			started.PlanID == "" || !started.Preview || started.State != "capturing" {
			t.Fatalf("MCP start export preview: %s", startData)
		}
		foreign := left
		if own.tenant == left.tenant {
			foreign = right
		}
		pageInput := mcp.NMSImportExportPageInput{ContextID: own.contextID,
			PlanID: foreign.planID, Resource: own.resource,
			PageNumber: 0, FirstRow: 0, Page: json.RawMessage(own.raw)}
		if _, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_export_page", pageInput); !failed {
			t.Fatal("MCP appended a page to a foreign tenant plan")
		}
		pageInput.PlanID = started.PlanID
		pageData, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_export_page", pageInput)
		var receipt mcp.NMSImportExportPageResult
		if failed || json.Unmarshal(pageData, &receipt) != nil || len(receipt.PageHash) != 64 ||
			strings.Contains(string(pageData), "source-secret") {
			t.Fatalf("MCP preview page did not redact source: %s", pageData)
		}
		sealData, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_export_seal", mcp.NMSImportExportSealInput{
				ContextID: own.contextID, PlanID: started.PlanID,
				ExpectedPages: 1, ExpectedRows: 1})
		var sealed mcp.NMSImportExportSealResult
		if failed || json.Unmarshal(sealData, &sealed) != nil || !sealed.Preview ||
			sealed.State != "sealed" || len(sealed.SnapshotHash) != 64 {
			t.Fatalf("MCP preview seal failed: %s", sealData)
		}
		rowsData, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_rows", mcp.NMSImportRowsInput{
				ContextID: own.contextID, PlanID: started.PlanID})
		var rows mcp.NMSImportRowsResult
		if failed || json.Unmarshal(rowsData, &rows) != nil ||
			len(rows.Items) != 1 || rows.Items[0].ExternalID != own.sourceID ||
			strings.Contains(string(rowsData), "source-secret") {
			t.Fatalf("MCP sealed preview rows lost source identity or redaction: %s", rowsData)
		}
	}
}
