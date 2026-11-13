// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestIncidentImpactExportCLIAndSDKKeepSelectionsAndSignedBytes(t *testing.T) {
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 10, 0, 0, 123456789, time.UTC)
	input := `{"impact":{"from":"2026-11-12T09:59:00.123456789Z","to":"2026-11-12T10:00:00.123456789Z","customer_tag_key":"customer","include_tests":true}}`
	for _, tenant := range []string{"tenant-red", "tenant-blue"} {
		id := "11111111-1111-4111-8111-111111111111"
		impact := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: id, EvaluatedAt: at,
			Current:  incident.ImpactPeriod{From: at.Add(-time.Minute), To: at, Coverage: "observed_attested_records", ObservedTotals: &incident.ImpactCounters{RawBytes: "18446744073709551615", RawPackets: "7", ScaledBytes: "55340232221128654845", ScaledPackets: "21"}, Captures: []incident.ImpactCaptureCitation{}},
			Previous: incident.ImpactPeriod{From: at.Add(-7*24*time.Hour - time.Minute), To: at.Add(-7 * 24 * time.Hour), Coverage: "no_observed_records", Captures: []incident.ImpactCaptureCitation{}}, Members: []incident.ImpactMember{}, Customers: []incident.ImpactCustomer{}, UnresolvedSignalIDs: []string{}}
		manifest, attachments, err := evidence.Build(evidence.BuildInput{TenantID: tenant, Incident: incident.Incident{ID: id}, CreatedAt: at, Impact: &impact})
		if err != nil {
			t.Fatal(err)
		}
		body, err := evidence.Sign(manifest, attachments, private)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/incidents/"+id+"/exports" || r.Header.Get("X-Probectl-Tenant") != tenant {
				t.Error("signed impact request changed its tenant or route")
			}
			var selected sdk.IncidentEvidenceExportInput
			if err := json.NewDecoder(r.Body).Decode(&selected); err != nil || selected.Impact.IncludeTests == nil || !*selected.Impact.IncludeTests || selected.Impact.CustomerTagKey != "customer" || selected.Impact.From != at.Add(-time.Minute).Format(time.RFC3339Nano) || selected.Impact.To != at.Format(time.RFC3339Nano) {
				t.Error("signed impact request changed exact selections", selected, err)
			}
			w.Header().Set("Content-Type", "application/vnd.probectl.evidence+json")
			_, _ = w.Write(body)
		}))
		t.Cleanup(server.Close)
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		env := func(name string) string {
			return map[string]string{"PROBECTL_API_URL": server.URL, "PROBECTL_CA_FILE": ca}[name]
		}
		var stdout, stderr bytes.Buffer
		if code := RunWithStdin([]string{"--tenant", tenant, "incident", "export", id, "--body-file", "-"}, env, strings.NewReader(input), &stdout, &stderr); code != 0 || !bytes.Equal(bytes.TrimSpace(stdout.Bytes()), body) {
			t.Fatal("CLI did not preserve complete signed bytes or stdin selections", code, stderr.String())
		}
		if _, err := evidence.Verify(stdout.Bytes()); err != nil {
			t.Fatal("CLI export changed the canonical signed manifest", err)
		}
		var selection sdk.IncidentEvidenceExportInput
		if err := json.Unmarshal([]byte(input), &selection); err != nil {
			t.Fatal(err)
		}
		client := sdk.NewClient(server.URL, sdk.WithHTTPClient(server.Client()), sdk.WithTenant(tenant))
		out, err := client.ExportIncidentEvidence(t.Context(), sdk.ExportIncidentEvidenceRequest{Id: id, Body: &selection})
		if err != nil || out == nil || len(out.Attachments) != 1 {
			t.Fatal("generated SDK lost the signed impact attachment", err)
		}
	}
}
