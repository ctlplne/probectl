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
	"testing"

	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Reuses the issued-mTLS/PG app-role RLS/HTTPS fixture. Input measurements
// are modeled; persistence, generated SDK and stored-reader controls are real.
func proveCarrierSLASignedReport(t *testing.T, client *sdk.Client, agreement, at, populationDigest string) string {
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
	manifest, err := evidence.Verify(signed.Bytes())
	if err != nil || manifest.Profile != "carrier-sla" {
		t.Fatal("stored claim cannot verify with existing offline verifier", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(signed.Bytes(), &pkg); err != nil || len(pkg.Attachments) != 2 {
		t.Fatal("claim or original attachment missing", err)
	}
	if !bytes.Contains(pkg.Attachments[0].Content, []byte(populationDigest)) || !bytes.Contains(pkg.Attachments[0].Content, []byte(agreement)) || !bytes.Contains(pkg.Attachments[1].Content, []byte(`"transmitted":3`)) || !bytes.Contains(pkg.Attachments[1].Content, []byte(`"round_trips"`)) {
		t.Fatal("signed report changed recorded circuit or complete original measurements")
	}
	changed := bytes.Replace(signed.Bytes(), []byte(`"transmitted":3`), []byte(`"transmitted":4`), 1)
	if _, err := evidence.Verify(changed); err == nil {
		t.Fatal("tampered stored original measurements verified")
	}
	return artifact.Id
}
