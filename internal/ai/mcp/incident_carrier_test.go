// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestNativeCarrierKeepsVerifiedSignedBytesAndRejectsForeignOrTamperedPackages(t *testing.T) {
	tenant, id := "11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	to := time.Now().UTC()
	from := to.Add(-time.Hour)
	pack := incident.CarrierPack{ContractVersion: incident.CarrierContractVersion, IncidentID: id, GeneratedAt: to, From: from, To: to, Summary: "Original selected window; missing evidence remains unknown.", Interpretation: "Temporal association is not proof of carrier fault.", Coverage: incident.CarrierCoverage{Measurements: "unavailable", Traces: "unavailable", Routing: "unavailable", Handoffs: "unavailable", Missing: []string{"independent_agent_traceroutes"}}, Vantages: []incident.CarrierVantage{}, Routing: []change.Event{}, Handoffs: []incident.CarrierHandoff{}}
	original := incident.Incident{ID: id, Status: incident.StatusOpen, Severity: incident.SeverityWarning, StartedAt: from, LastSeenAt: to}
	manifest, attachments, err := evidence.Build(evidence.BuildInput{TenantID: tenant, Incident: original, CreatedAt: to, Carrier: &pack})
	if err != nil {
		t.Fatal(err)
	}
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	raw, err := evidence.Sign(manifest, attachments, private)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSignedCarrierResult(raw, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	server := nativeProbeServer(&nativeBackendProbe{}, nil)
	response, err := server.redactedToolResult(tenant, result, true)
	if err != nil {
		t.Fatal(err)
	}
	framed, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Structured struct {
			IncidentID string `json:"incident_id"`
			Package    string `json:"package"`
			Encoding   string `json:"encoding"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(framed, &wire); err != nil {
		t.Fatal(err)
	}
	restored, err := base64.StdEncoding.Strict().DecodeString(wire.Structured.Package)
	if err != nil || wire.Structured.IncidentID != id || wire.Structured.Encoding != "base64" || !bytes.Equal(restored, raw) {
		t.Fatal("native redaction/framing changed verified carrier bytes", err)
	}
	if _, err := evidence.Verify(restored); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignedCarrierResult(raw, "22222222-2222-4222-8222-222222222222", id); err == nil {
		t.Fatal("foreign scope constructed a native signed carrier")
	}
	if _, err := NewSignedCarrierResult(raw, tenant, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"); err == nil {
		t.Fatal("foreign incident constructed a native signed carrier")
	}
	var changed evidence.Package
	if err := json.Unmarshal(raw, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Attachments[0].Content = json.RawMessage(`{"summary":"tampered"}`)
	invalid, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignedCarrierResult(invalid, tenant, id); err == nil {
		t.Fatal("tampered signed bytes entered native carrier framing")
	}
}
