// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func (p *clientReportNativeProof) proveAssessmentFlowSample(tenant, foreign string, definition dashboardDefinition, expected, artifactID string) {
	p.t.Helper()
	p.artifacts[tenant] = artifactID
	client := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]))
	check := func(id string) {
		p.t.Helper()
		var body bytes.Buffer
		if _, err := client.DownloadDashboardReportArtifactTo(p.t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id}, &body, 64<<20); err != nil {
			p.t.Fatal(err)
		}
		if err := checkAssessmentFlowSampleCSV(body.Bytes(), foreign, expected); err != nil {
			p.t.Fatal("native combined sample changed complete source results", err)
		}
	}
	caller := reportMCPClient{t: p.t, socket: p.native, foreignTenant: foreign}
	var view mcp.ReportDashboard
	caller.call(p.fixture.tokens[tenant], "report_dashboard_save", reporting.DashboardCreateInput{Name: "Native assessment flow sample", Preset: "operator", Definition: definition}, &view, true, "native combined assessment configuration refused")
	if view.TenantID != tenant || view.Definition.ClientReport == nil || len(view.Definition.FlowSources) != 1 || view.Definition.FlowSources[0] != definition.FlowSources[0] {
		p.t.Fatal("native assessment adopted a different tenant source")
	}
	manifest, code := p.invokeCLI(tenant, nil, "dashboard", "export", view.ID)
	if code != 0 || bytes.Contains(manifest, []byte(definition.FlowSources[0].ID)) {
		p.t.Fatal("CLI assessment manifest retained a tenant query identity", code)
	}
	var portable reporting.DashboardManifest
	if err := json.Unmarshal(manifest, &portable); err != nil || len(portable.Spec.Definition.FlowSources) != 1 || portable.Spec.Definition.ClientReport == nil {
		p.t.Fatal("CLI lost combined assessment source slots", err)
	}
	var imported mcp.ReportImportResult
	slot := portable.Spec.Definition.FlowSources[0].Slot
	caller.call(p.fixture.tokens[tenant], "report_dashboard_import", reporting.DashboardManifestImportInput{Manifest: portable, SourceBindings: map[string]reporting.FlowSourceRef{slot: definition.FlowSources[0]}}, &imported, true, "native assessment sample preview refused its explicit destination binding")
	if imported.Status != "preview" || imported.Dashboard != nil {
		p.t.Fatal("native assessment sample preview changed retained state")
	}
	var schedule mcp.ReportSchedule
	caller.call(p.fixture.tokens[tenant], "report_schedule_create", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Assessment sample delivery", Format: "csv", Cadence: "monthly", DestinationID: reportInboxDestination, FirstRunAt: time.Now().UTC().Add(time.Hour)}, &schedule, true, "native assessment sample schedule bypassed or lost its source preflight")
	if schedule.ID == "" {
		p.t.Fatal("native assessment sample schedule omitted its identity")
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		if wire == "2025-11-25" {
			proveLegacyMCPInitializationTLS(p.t, p.native, p.fixture.tokens[tenant])
		}
		httpClient := reportMCPClient{t: p.t, socket: p.native, foreignTenant: foreign, protocolVersion: wire}
		var generated mcp.ReportArtifact
		httpClient.call(p.fixture.tokens[tenant], "report_generate", reporting.ReportGenerateInput{DashboardID: view.ID, Format: "csv"}, &generated, true, "native combined assessment generation refused")
		check(generated.ID)
		if p.stdio[wire] == nil {
			p.stdio[wire] = map[string]*interfaceRoleStdioClient{}
		}
		stream := openInterfaceRoleStdio(p.t, p.server, p.authenticator, p.fixture.tokens[tenant], wire, 5*time.Minute)
		p.stdio[wire][tenant] = stream
		stream.call(p.t, wire, "report_generate", reporting.ReportGenerateInput{DashboardID: view.ID, Format: "csv"}, &generated, true)
		check(generated.ID)
		httpClient.call(p.fixture.tokens[tenant], "report_generate", map[string]any{"dashboard_id": view.ID, "format": "csv", "tenant_id": foreign}, nil, false, "native assessment accepted a tenant override")
	}
	request, err := json.Marshal(reporting.ReportGenerateInput{DashboardID: view.ID, Format: "csv"})
	if err != nil {
		p.t.Fatal(err)
	}
	metadata, code := p.invokeCLI(tenant, request, "dashboard-report", "generate", "--body-file", "-")
	if code != 0 {
		p.t.Fatal("CLI combined assessment generation refused", code)
	}
	var generated reportArtifactView
	if err := json.Unmarshal(metadata, &generated); err != nil || generated.ID == "" {
		p.t.Fatal(err)
	}
	downloaded, code := p.invokeCLI(tenant, nil, "dashboard-report", "download", generated.ID)
	if code != 0 {
		p.t.Fatal("CLI combined assessment download refused", code)
	}
	if err := checkAssessmentFlowSampleCSV(downloaded, foreign, expected); err != nil {
		p.t.Fatal(err)
	}
}

func denyAssessmentSampleNative(t *testing.T, p *clientReportNativeProof, tenant, foreign string) {
	t.Helper()
	caller := reportMCPClient{t: t, socket: p.native, foreignTenant: foreign}
	caller.call(p.fixture.tokens[tenant], "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, nil, false, "native flow receipt bypassed assessment source withdrawal")
	for wire, streams := range p.stdio {
		streams[tenant].call(t, wire, "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, nil, false)
	}
}
