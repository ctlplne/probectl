// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual paired PG/ClickHouse sources, tokens and TLS MCP. The legacy path
// store is unused by these report calls; this is not four-store release proof.
func proveReportsMCP(t *testing.T, f *tagImportSubjectFixture, rest *httptest.Server, proofs []*reportDownloadProof, writes bool) {
	t.Helper()
	cfg := &config.Config{}
	server := NewMCPServerWithPolicyLoader(cfg, f.srv.log, f.srv.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.srv.log, f.srv.pool), nil, nil, f.srv.MCPPolicyLoader(), AISources{NativeFlow: f.srv})
	socket := httptest.NewTLSServer(server.HTTPHandler(NewMCPAuthenticator(f.srv.pool, NewTenantStatusCache(f.srv.pool, 0), false)))
	defer socket.Close()
	for i, proof := range proofs {
		client := reportMCPClient{t: t, socket: socket, foreignTenant: proofs[1-i].tenant}
		var dashboards mcp.ReportDashboardList
		client.call(proof.token, "report_dashboards", map[string]any{}, nil, false, "unconsented report MCP exposed current dashboards")
		consentCapturedReportMCP(t, f, proof)
		client.call(proof.token, "report_dashboards", map[string]any{}, &dashboards, true, "current report MCP list failed")
		if len(dashboards.Items) == 0 {
			t.Fatal("report MCP lost current dashboards")
		}
		for _, view := range dashboards.Items {
			if view.TenantID != proof.tenant {
				t.Fatal("MCP dashboard list crossed tenant storage scope")
			}
		}
		var view mcp.ReportDashboard
		client.call(proof.token, "report_dashboard", map[string]any{"id": dashboards.Items[0].ID}, &view, true, "current report MCP get failed")
		var artifacts mcp.ReportArtifactList
		client.call(proof.token, "report_artifacts", map[string]any{}, &artifacts, true, "current report MCP artifact list failed")
		if len(artifacts.Items) == 0 {
			t.Fatal("report MCP lost authorized source artifacts")
		}
		var link mcp.ReportArtifactLink
		client.call(proof.token, "report_artifact_link", map[string]any{"id": "same-source-artifact"}, &link, true, "current report MCP link failed")
		if !link.AuthenticationRequired || link.Artifact.BodySHA256 != proof.digest || link.Artifact.BodyBytes != int64(len(proof.expected)) || link.Artifact.DownloadURL != "/v1/dashboard-report-artifacts/same-source-artifact" {
			t.Fatal("MCP link is not exact authenticated stored metadata")
		}
		client.call(proof.scopedToken, "report_artifact_link", map[string]any{"id": "same-source-artifact"}, nil, false, "scoped MCP reader received a private report link")
		client.call(proof.token, "report_artifact_link", map[string]any{"id": proofs[1-i].foreignID}, nil, false, "foreign MCP report link escaped current tenant")
		client.call(proof.token, "report_artifact_link", map[string]any{"id": "same-source-artifact", "tenant_id": proofs[1-i].tenant}, nil, false, "MCP report arguments accepted a tenant override")
		var limited mcp.ReportArtifactList
		client.call(proof.scopedToken, "report_artifacts", map[string]any{}, &limited, true, "scoped metadata list did not remain available")
		if len(limited.Items) != 0 {
			t.Fatal("scoped MCP report list exposed private sources")
		}
		if writes {
			proveReportMCPWrites(t, client, proof)
		}
	}
	client := reportMCPClient{t: t, socket: socket, foreignTenant: proofs[1].tenant}
	original := f.srv.flowRenderBudget
	f.srv.flowRenderBudget.SourceBytes = 1
	func() {
		defer func() { f.srv.flowRenderBudget = original }()
		client.call(proofs[0].token, "report_dashboard", map[string]any{"id": "same-source-view"}, nil, false, "bounded report bridge returned a partial or over-budget MCP result")
	}()
	proveReportMCPFreshSource(t, f, rest, client, proofs[0])
}

func proveReportMCPWrites(t *testing.T, client reportMCPClient, proof *reportDownloadProof) {
	t.Helper()
	input := reporting.DashboardCreateInput{Name: "MCP source report", Preset: "operator", Shared: true, Definition: reporting.DashboardDefinition{FlowSources: proof.sources, Provenance: []string{"saved source"}, RedactionState: "current source policy", CoverageLimitations: []string{"selected source rows only"}}}
	var view mcp.ReportDashboard
	client.call(proof.token, "report_dashboard_save", input, &view, true, "MCP source save failed")
	if view.TenantID != proof.tenant || view.OwnerID != proof.user {
		t.Fatal("MCP source save lost credential-derived identity")
	}
	var manifest reporting.DashboardManifest
	client.call(proof.token, "report_dashboard_export", map[string]any{"id": view.ID}, &manifest, true, "MCP source manifest export failed")
	if len(manifest.Spec.Definition.FlowSources) != 1 || manifest.Spec.Definition.FlowSources[0].Slot != "flow-1" {
		t.Fatal("MCP export lost portable source slots")
	}
	native := reporting.DashboardManifestImportInput{Manifest: manifest, SourceBindings: map[string]reporting.FlowSourceRef{"flow-1": proof.sources[0]}}
	var preview mcp.ReportImportResult
	client.call(proof.token, "report_dashboard_import", native, &preview, true, "MCP native preview failed")
	if preview.Status != "preview" || preview.Dashboard != nil || preview.Preview.SourceCount != 1 {
		t.Fatal("MCP native preview created state")
	}
	native.Confirm = true
	var imported mcp.ReportImportResult
	client.call(proof.token, "report_dashboard_import", native, &imported, true, "MCP confirmed native import failed")
	if imported.Status != "created" || imported.Dashboard == nil || imported.Dashboard.TenantID != proof.tenant {
		t.Fatal("MCP native import lost destination tenant")
	}
	var schedule mcp.ReportSchedule
	client.call(proof.token, "report_schedule_create", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "MCP source schedule", Format: "csv", Cadence: "daily", DestinationID: reportInboxDestination, FirstRunAt: time.Now().UTC().Add(time.Hour)}, &schedule, true, "MCP source schedule creation failed")
	for _, enabled := range []bool{false, true} {
		var updated mcp.ReportSchedule
		client.call(proof.token, "report_schedule_update", mcp.ReportScheduleUpdateInput{ID: schedule.ID, Enabled: &enabled}, &updated, true, "MCP current schedule update failed")
		if updated.ID != schedule.ID || updated.Enabled != enabled {
			t.Fatal("MCP schedule mutation lost explicit state")
		}
	}
	var schedules mcp.ReportScheduleList
	client.call(proof.token, "report_schedules", map[string]any{}, &schedules, true, "MCP current schedules failed")
	if len(schedules.Items) == 0 || schedules.OutboundDefault {
		t.Fatal("MCP source schedules lost local-only destination")
	}
	var artifact mcp.ReportArtifact
	client.call(proof.token, "report_generate", reporting.ReportGenerateInput{DashboardID: view.ID, Format: "csv"}, &artifact, true, "MCP current source generation failed")
	if artifact.ID == "" || artifact.Format != "csv" {
		t.Fatal("MCP source generation lost artifact identity")
	}
	var link mcp.ReportArtifactLink
	client.call(proof.token, "report_artifact_link", map[string]any{"id": artifact.ID}, &link, true, "MCP generated report link failed")
	if !link.AuthenticationRequired || link.Artifact.BodyBytes <= 0 {
		t.Fatal("MCP generated artifact link lost complete stored metadata")
	}
}

func proveReportMCPFreshSource(t *testing.T, f *tagImportSubjectFixture, rest *httptest.Server, client reportMCPClient, proof *reportDownloadProof) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(proof.tenant))
	var reader string
	if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "mcp-reader@"+proof.tenant+".invalid", "Broad report reader")
		if err != nil {
			return err
		}
		reader = user.ID
		return (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, proof.role)
	}); err != nil {
		t.Fatal(err)
	}
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.db.Pool()).CreateWithLifetime(ctx, proof.tenant, reader, "private-report-reader", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	client.call(token, "report_artifact_link", map[string]any{"id": "same-source-artifact"}, nil, false, "broad MCP reader borrowed private source ownership")
	if err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, proof.tenant, proof.role, permFlowRead)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := tenancy.InTenant(tenancy.WithTenant(cleanup, tenancy.ID(proof.tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, proof.role, permFlowRead)
		}); err != nil {
			t.Fatal("restore MCP source role fixture", err)
		}
	}
	defer restore()
	client.call(proof.token, "report_artifact_link", map[string]any{"id": "same-source-artifact"}, nil, false, "revoked current MCP source role retained a report link")
	status, headers, body := requestCapturedReport(t, rest, proof.token, "same-source-artifact")
	if status == http.StatusOK || headers.Get("X-Report-SHA256") != "" || bytes.Contains(body, proof.expected) {
		t.Fatal("prior MCP report link acted as a binary access grant")
	}
}
