// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Reuses the issued-mTLS/PG app-role RLS/HTTPS fixture. Input measurements
// are modeled; persistence, generated SDK and stored-reader controls are real.
type carrierSLAReportProof struct{ CSV, PDF, View, Scheduled, PopulationDigest string }
type carrierSLAReportContextWant struct {
	roundID, flowBytes string
	lateFlowTime       time.Time
}

func proveCarrierSLASignedReport(t *testing.T, client *sdk.Client, agreement, at, populationDigest, fingerprint string, want carrierSLAReportContextWant) carrierSLAReportProof {
	t.Helper()
	input := sdk.DashboardCreateRequest{Name: "Signed carrier claim", Preset: "operator", Definition: sdk.DashboardDefinition{CarrierClaim: &sdk.CarrierSLAReportDefinition{Selections: []sdk.CarrierSLAReportSelection{{AgreementId: agreement, Version: "1", At: at}}}, Provenance: []string{"recorded circuit SLA"}, RedactionState: "tenant policy", CoverageLimitations: []string{"observed originals only"}}}
	view, err := client.CreateDashboard(t.Context(), sdk.CreateDashboardRequest{Body: &input})
	if err != nil {
		t.Fatal("current-tenant financial report configuration failed", err)
	}
	body := map[string]any{"dashboard_id": view.Id, "format": "csv"}
	artifact, err := client.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &body})
	if err != nil {
		t.Fatal("signed financial report generation failed", err)
	}
	var downloaded bytes.Buffer
	_, err = client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}, &downloaded, 1<<30)
	content := downloaded.Bytes()
	if err != nil {
		t.Fatal("stored signed financial artifact unavailable", err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	chunks := 0
	for _, row := range rows {
		if len(row) != 6 || len(row[0]) < 4 || row[0][:4] != "pkg_" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(row[5])
		if err != nil {
			t.Fatal("complete evidence chunk encoding failed", err)
		}
		signed.Write(raw)
		chunks++
	}
	if chunks == 0 {
		t.Fatal("generated artifact omitted signed evidence")
	}
	proveCarrierSLASignedBytes(t, signed.Bytes(), agreement, populationDigest, fingerprint, want)
	body["format"] = "pdf"
	pdf, err := client.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &body})
	if err != nil {
		t.Fatal("complete financial PDF generation failed", err)
	}
	var pdfBody bytes.Buffer
	if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: pdf.Id}, &pdfBody, 1<<30); err != nil {
		t.Fatal("stored financial PDF unavailable", err)
	}
	attachment := regexp.MustCompile(`/Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size ([0-9]+) >> /Length ([0-9]+) >>\nstream\n`).FindSubmatchIndex(pdfBody.Bytes())
	if attachment == nil {
		t.Fatal("served PDF lost the complete attached signed originals")
	}
	length, err := strconv.ParseInt(string(pdfBody.Bytes()[attachment[4]:attachment[5]]), 10, 64)
	if err != nil || length <= 0 || length > int64(pdfBody.Len()-attachment[1]) {
		t.Fatal("served PDF attachment length is invalid", err)
	}
	proveCarrierSLASignedBytes(t, pdfBody.Bytes()[attachment[1]:attachment[1]+int(length)], agreement, populationDigest, fingerprint, want)
	return carrierSLAReportProof{CSV: artifact.Id, PDF: pdf.Id, View: view.Id, PopulationDigest: populationDigest}
}

func proveCarrierSLASignedBytes(t *testing.T, signed []byte, agreement, populationDigest, fingerprint string, expected ...carrierSLAReportContextWant) {
	t.Helper()
	manifest, err := evidence.Verify(signed)
	if err != nil || manifest.Profile != "carrier-sla" {
		t.Fatal("claim cannot verify offline", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(signed, &pkg); err != nil || len(pkg.Attachments) != 2 || pkg.Signing.Fingerprint != fingerprint {
		t.Fatal("claim or original attachment or trusted deployment signer changed", err)
	}
	if !bytes.Contains(pkg.Attachments[0].Content, []byte(populationDigest)) || !bytes.Contains(pkg.Attachments[0].Content, []byte(agreement)) || !bytes.Contains(pkg.Attachments[1].Content, []byte(`"transmitted":3`)) || !bytes.Contains(pkg.Attachments[1].Content, []byte(`"round_trips"`)) {
		t.Fatal("signed report changed recorded circuit or complete original measurements")
	}
	if len(expected) > 0 {
		want := expected[0]
		var originals struct {
			Selections []struct {
				EvidenceBefore time.Time                `json:"evidence_before"`
				PathCoverage   string                   `json:"path_coverage"`
				Rounds         []carrierSLAPathOriginal `json:"path_rounds"`
				FlowCoverage   string                   `json:"flow_coverage"`
				Flows          []carrierSLAFlowOriginal `json:"flow_records"`
			} `json:"selections"`
		}
		if err := json.Unmarshal(pkg.Attachments[1].Content, &originals); err != nil || len(originals.Selections) != 1 ||
			originals.Selections[0].PathCoverage != "control_plane_context" || len(originals.Selections[0].Rounds) != 1 ||
			originals.Selections[0].Rounds[0].RoundID != want.roundID ||
			originals.Selections[0].Rounds[0].Path.Vantage != "control_plane" {
			t.Fatal("signed report lost the exact owned control-plane path", err)
		}
		selection := originals.Selections[0]
		if want.lateFlowTime.Add(time.Millisecond).After(selection.EvidenceBefore) {
			t.Fatal("the late flow would fall outside the signed evidence cutoff")
		}
		if selection.FlowCoverage != "attested_flow_context" || len(selection.Flows) != 1 || selection.Flows[0].Bytes != want.flowBytes ||
			selection.Flows[0].Packets != "7" || selection.Flows[0].Sampling != "3" || selection.Flows[0].OriginalSourceID == "" ||
			selection.Flows[0].InIf != 7 || selection.Flows[0].OutIf != 7 || selection.Flows[0].ClockBasis != "exporter_interval" ||
			bytes.Contains(pkg.Attachments[1].Content, []byte("203.0.113.")) {
			t.Fatal("signed report changed raw counters, included an unproven clock or revealed unrelated traffic")
		}
	}
	file := filepath.Join(t.TempDir(), "carrier-claim.json")
	if err := os.WriteFile(file, signed, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.RunWithStdin([]string{"incident", "verify", file, "--trusted-key-fingerprint", fingerprint}, func(string) string { return "" }, nil, &stdout, &stderr)
	if code != 0 || !bytes.Contains(stdout.Bytes(), []byte("VERIFIED probectl-evidence/v1")) {
		t.Fatal("actual offline CLI rejected complete signed claim", code, stderr.String())
	}
	changed := bytes.Replace(signed, []byte(`"transmitted":3`), []byte(`"transmitted":4`), 1)
	if _, err := evidence.Verify(changed); err == nil {
		t.Fatal("tampered stored original measurements verified")
	}
}

func proveCarrierSLASignedWithoutFlow(t *testing.T, client *sdk.Client, proof carrierSLAReportProof, agreement, fingerprint string) string {
	t.Helper()
	body := map[string]any{"dashboard_id": proof.View, "format": "csv"}
	artifact, err := client.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &body})
	if err != nil || artifact == nil || artifact.Id == "" {
		t.Fatal("an unavailable flow must leave the signed claim publishable", err)
	}
	raw, err := client.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id})
	if err != nil {
		t.Fatal("the signed claim without optional flow evidence was unavailable", err)
	}
	signed := carrierMonthWorkloadPackage(t, "csv", raw)
	proveCarrierSLASignedBytes(t, signed, agreement, proof.PopulationDigest, fingerprint)
	var envelope evidence.Package
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	var originals struct {
		Selections []struct {
			PathCoverage string            `json:"path_coverage"`
			FlowCoverage string            `json:"flow_coverage"`
			Flows        []json.RawMessage `json:"flow_records"`
		} `json:"selections"`
	}
	if err := json.Unmarshal(envelope.Attachments[1].Content, &originals); err != nil || len(originals.Selections) != 1 ||
		originals.Selections[0].FlowCoverage != "unavailable" || len(originals.Selections[0].Flows) != 0 ||
		originals.Selections[0].PathCoverage != "control_plane_context" {
		t.Fatal("the signed claim lost coverage labels or disclosed flows without authority", err)
	}
	return artifact.Id
}

// Exercise the shipping report backend under each supported wire revision and
// both actual transports. No direct handler call substitutes for publication.
func (p *clientReportNativeProof) proveCarrier(t *testing.T, tenant, foreign string, proof carrierSLAReportProof, agreement, fingerprint string) {
	t.Helper()
	client := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]))
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		caller := reportMCPClient{t: t, socket: p.native, foreignTenant: foreign, protocolVersion: wire}
		var selected mcp.ReportDashboard
		caller.call(p.fixture.tokens[tenant], "report_dashboard", map[string]any{"id": proof.View}, &selected, true, "native financial view unavailable")
		if selected.Definition.CarrierClaim == nil || len(selected.Definition.CarrierClaim.Selections) != 1 || selected.Definition.CarrierClaim.Selections[0].AgreementID != agreement || selected.Definition.CarrierClaim.Selections[0].Version != "1" {
			t.Fatal("native view changed the exact financial selection")
		}
		var artifact mcp.ReportArtifact
		caller.call(p.fixture.tokens[tenant], "report_generate", reporting.ReportGenerateInput{DashboardID: proof.View, Format: "csv"}, &artifact, true, "native complete financial generation failed")
		proveCarrierSLANativeArtifact(t, client, artifact.ID, agreement, proof.PopulationDigest, fingerprint)
		if p.stdio[wire] == nil {
			p.stdio[wire] = map[string]*interfaceRoleStdioClient{}
		}
		stream := openInterfaceRoleStdio(t, p.server, p.authenticator, p.fixture.tokens[tenant], wire, 5*time.Minute)
		p.stdio[wire][tenant] = stream
		stream.call(t, wire, "report_generate", reporting.ReportGenerateInput{DashboardID: proof.View, Format: "csv"}, &artifact, true)
		proveCarrierSLANativeArtifact(t, client, artifact.ID, agreement, proof.PopulationDigest, fingerprint)
		p.artifacts[tenant] = artifact.ID
	}
}

func proveCarrierSLANativeArtifact(t *testing.T, client *sdk.Client, id, agreement, digest, fingerprint string) {
	t.Helper()
	var body bytes.Buffer
	if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id}, &body, 1<<30); err != nil {
		t.Fatal("native generated financial artifact unavailable", err)
	}
	reader := csv.NewReader(&body)
	reader.FieldsPerRecord = -1
	var signed bytes.Buffer
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(row) == 6 && len(row[0]) > 4 && row[0][:4] == "pkg_" {
			raw, err := base64.StdEncoding.DecodeString(row[5])
			if err != nil {
				t.Fatal(err)
			}
			signed.Write(raw)
		}
	}
	proveCarrierSLASignedBytes(t, signed.Bytes(), agreement, digest, fingerprint)
}

func (p *clientReportNativeProof) carrierReadAllowed(t *testing.T, tenant string, allowed bool) {
	t.Helper()
	for wire, streams := range p.stdio {
		caller := reportMCPClient{t: t, socket: p.native, protocolVersion: wire}
		var link mcp.ReportArtifactLink
		caller.call(p.fixture.tokens[tenant], "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, &link, allowed, "financial report current source authority changed")
		streams[tenant].call(t, wire, "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, &link, allowed)
	}
}

// A stored signature is not a retained financial grant. Exercise withdrawal,
// restoration and a later immutable financial revision with all sources live.
func proveCarrierFinancialReportAuthority(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, native *clientReportNativeProof, tenant string, proof carrierSLAReportProof, agreement flow.CapacityAgreement) {
	t.Helper()
	downloads := func(allowed bool, phase string) {
		t.Helper()
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		for _, id := range []string{proof.CSV, proof.PDF, proof.Scheduled} {
			raw, err := client.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id})
			if allowed && (err != nil || len(raw) == 0) || !allowed && (err == nil || len(raw) != 0) {
				t.Fatal("financial report current-authority boundary failed", phase, allowed, err)
			}
		}
		native.carrierReadAllowed(t, tenant, allowed)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permFlowAgreementsRead)
		return err
	})
	downloads(false, "withdrawn")
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permFlowAgreementsRead)
	})
	downloads(true, "restored")
	request := httptest.NewRequest("GET", "/v1/dashboard-report-artifacts/"+proof.CSV, nil)
	request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
	actor := f.server.resolvePrincipal(request)
	if actor == nil {
		t.Fatal("current financial source-publication control did not authenticate")
	}
	var captured *reportFlowCapture
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		metadata, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, proof.CSV, f.users[tenant], 8<<20)
		if err != nil {
			return err
		}
		captured, err = parseReportSourceRequirements(ctx, metadata.SourceCapture, 8<<20)
		return err
	})
	from, err := time.Parse(time.RFC3339Nano, agreement.Definition.ValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	replacement := agreement.Definition
	replacement.ValidFrom = from.AddDate(0, 1, 0).Format(time.RFC3339Nano)
	replacement.Reference = "Later recorded terms; prior artifact remains pinned"
	repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
	next, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{ID: agreement.ID, Version: agreement.Version, Definition: replacement})
	if err != nil || next.Version == agreement.Version {
		t.Fatal("actual financial revision control failed", err)
	}
	// All current grants, exact old terms and original sources are still
	// valid. An unrelated future revision cannot revoke this historical pack.
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	input := sdk.CarrierSLAInput{Version: agreement.Version, At: from.Add(time.Hour).Format(time.RFC3339Nano)}
	current, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: agreement.ID, Body: &input})
	if err != nil || current == nil || current.Agreement.CurrentVersion != next.Version {
		t.Fatal("unchanged prior source-period no longer readable independently", err)
	}
	downloads(true, "future terms")
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		ctx = store.WithReportSourceAuditLock(auth.WithPrincipal(ctx, actor), sc)
		if err := f.server.validateReportSourcePublication(ctx, sc, actor, captured); err == nil {
			t.Fatal("a stale captured financial head acquired new publication authority")
		}
		if err := f.server.revalidateReportFlowCaptureScope(ctx, sc, actor, captured); err != nil {
			t.Fatal("unchanged historical reader lost its current authority", err)
		}
		return nil
	})
}
