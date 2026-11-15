// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Reuses the issued-mTLS/PG app-role RLS/HTTPS fixture. Input measurements
// are modeled; persistence, generated SDK and stored-reader controls are real.
type carrierSLAReportProof struct{ CSV, PDF, View, PopulationDigest string }

func proveCarrierSLASignedReport(t *testing.T, client *sdk.Client, agreement, at, populationDigest, fingerprint string) carrierSLAReportProof {
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
	proveCarrierSLASignedBytes(t, signed.Bytes(), agreement, populationDigest, fingerprint)
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
	proveCarrierSLASignedBytes(t, pdfBody.Bytes()[attachment[1]:attachment[1]+int(length)], agreement, populationDigest, fingerprint)
	return carrierSLAReportProof{CSV: artifact.Id, PDF: pdf.Id, View: view.Id, PopulationDigest: populationDigest}
}

func proveCarrierSLASignedBytes(t *testing.T, signed []byte, agreement, populationDigest, fingerprint string) {
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
