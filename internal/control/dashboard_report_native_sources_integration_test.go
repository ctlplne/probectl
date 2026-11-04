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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/store"
)

// Actual authenticated HTTPS and the real CLI library over the paired source
// fixture. Release binaries, browser rendering and four-store sender acceptance
// remain independent requirements; this does not replace those receipts.
func proveSourceReportNativeBindings(t *testing.T, f *tagImportSubjectFixture, socket *httptest.Server, proofs []*reportDownloadProof, views []store.DashboardView) {
	t.Helper()
	exported := make([]dashboardManifest, len(proofs))
	for i, proof := range proofs {
		status, body := reportProofJSON(t, socket, proof.token, http.MethodGet, "/v1/dashboards/"+views[i].ID+"/manifest", nil)
		if status != http.StatusOK {
			t.Fatal("source native export failed", status, string(body))
		}
		for _, identity := range []string{proof.tenant, proof.user, views[i].ID, proof.sources[0].ID} {
			if bytes.Contains(body, []byte(identity)) {
				t.Fatal("portable source manifest retained local identity")
			}
		}
		if err := json.Unmarshal(body, &exported[i]); err != nil {
			t.Fatal(err)
		}
		slots := exported[i].Spec.Definition.FlowSources
		if len(slots) != 1 || slots[0].Slot != "flow-1" {
			t.Fatal("native source export lost explicit portable slots")
		}
		status, _ = reportProofJSON(t, socket, proofs[1-i].token, http.MethodGet, "/v1/dashboards/"+views[i].ID+"/manifest", nil)
		if status != http.StatusNotFound {
			t.Fatal("native export crossed the current token tenant", status)
		}
	}
	target := proofs[1]
	count := func() int {
		t.Helper()
		var n int
		if err := f.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM dashboard_views WHERE tenant_id=$1`, target.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	request := dashboardManifestImportRequest{Manifest: exported[0]}
	status, _ := reportProofJSON(t, socket, target.token, http.MethodPost, "/v1/dashboard-manifests/import", request)
	if status != http.StatusUnprocessableEntity || count() != before {
		t.Fatal("native import invented a missing source binding", status)
	}
	request.SourceBindings = map[string]reportFlowSourceRef{"flow-1": proofs[0].sources[0]}
	status, _ = reportProofJSON(t, socket, target.token, http.MethodPost, "/v1/dashboard-manifests/import", request)
	if status != http.StatusNotFound || count() != before {
		t.Fatal("native binding accepted a foreign source identity", status)
	}
	request.SourceBindings["flow-1"] = reportFlowSourceRef{ID: target.sources[0].ID, Version: "999"}
	status, _ = reportProofJSON(t, socket, target.token, http.MethodPost, "/v1/dashboard-manifests/import", request)
	if status != http.StatusConflict || count() != before {
		t.Fatal("native binding silently refreshed a stale source version", status)
	}
	request.SourceBindings["flow-1"] = target.sources[0]
	status, body := reportProofJSON(t, socket, target.token, http.MethodPost, "/v1/dashboard-manifests/import", request)
	var preview dashboardManifestImportResponse
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || preview.Status != "preview" || preview.Dashboard != nil || preview.Preview.SourceCount != 1 || count() != before {
		t.Fatal("native binding preview created state or lost source metadata", status)
	}
	directory := t.TempDir()
	caFile, bindingFile := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "source-bindings.json")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	bindingJSON, err := json.Marshal(request.SourceBindings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingFile, bindingJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(preview.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	env := func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return socket.URL
		case "PROBECTL_API_TOKEN":
			return target.token
		case "PROBECTL_CA_FILE":
			return caFile
		}
		return ""
	}
	invoke := func(confirm bool) dashboardManifestImportResponse {
		t.Helper()
		args := []string{"dashboard", "import", "--source-bindings-file", bindingFile}
		if confirm {
			args = append(args, "--confirm")
		}
		var output, errors bytes.Buffer
		code := cli.RunWithStdin(args, env, bytes.NewReader(manifestJSON), &output, &errors)
		if code != 0 {
			t.Fatal("actual CLI source binding import failed", code, errors.String())
		}
		var result dashboardManifestImportResponse
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := invoke(false); result.Status != "preview" || result.Dashboard != nil || count() != before {
		t.Fatal("CLI native preview created a dashboard")
	}
	created := invoke(true)
	if created.Status != "created" || created.Dashboard == nil || created.Dashboard.TenantID != target.tenant || created.Dashboard.OwnerID != target.user || count() != before+1 {
		t.Fatal("CLI confirmed source import lost destination identity")
	}
	var definition dashboardDefinition
	if err := json.Unmarshal(created.Dashboard.Definition, &definition); err != nil {
		t.Fatal(err)
	}
	if len(definition.FlowSources) != 1 || definition.FlowSources[0] != target.sources[0] {
		t.Fatal("native source import copied source tenant references")
	}
	status, body = reportProofJSON(t, socket, target.token, http.MethodPost, "/v1/dashboard-reports", reportGenerateRequest{DashboardID: created.Dashboard.ID, Format: target.format})
	if status != http.StatusCreated {
		t.Fatal("native-bound source report generation failed", status, string(body))
	}
	var artifact reportArtifactView
	if err := json.Unmarshal(body, &artifact); err != nil {
		t.Fatal(err)
	}
	status, _, body = requestCapturedReport(t, socket, target.token, artifact.ID)
	if status != http.StatusOK || len(body) == 0 {
		t.Fatal("native-bound source report download failed", status)
	}
	if target.format == "csv" && (!bytes.Contains(body, []byte("OWN-"+target.tenant)) || bytes.Contains(body, []byte("OWN-"+proofs[0].tenant))) {
		t.Fatal("native-bound generation used the original tenant's data")
	}
}
