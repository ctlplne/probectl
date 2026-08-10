// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestSignedPackageRoundTripAndTamperRejection(t *testing.T) {
	privatePEM, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	redacted := incident.Incident{
		ID: "30000000-0000-4000-8000-000000000001", Status: incident.StatusOpen,
		Severity: incident.SeverityCritical, Title: "Intermittent ISP loss", Target: "[ip]",
		StartedAt: now.Add(-45 * time.Second), LastSeenAt: now.Add(45 * time.Second), SignalCount: 1,
		Signals: []incident.Signal{{
			Plane: "network", Kind: "path.loss", Severity: incident.SeverityCritical,
			Title: "Terminal loss observed", Summary: "Customer edge stopped responding", Target: "[ip]", OccurredAt: now,
			Attributes: map[string]string{"vantage_id": "branch-a", "vantage_owner": "customer-owned", "trust_tier": "tenant-mtls", "independence": "independent-site", "clock_quality": "ntp-skew-under-2s", "sample_cadence_seconds": "5"},
		}},
	}
	manifest, attachments, err := Build(BuildInput{TenantID: "tenant-a", Incident: redacted, CreatedAt: now, Conclusion: "The ISP fault domain best explains the loss.", Grounded: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(manifest, attachments, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Contract != ContractVersion || len(verified.Evidence) != 1 || verified.Statements[len(verified.Statements)-1].Class != "inference" {
		t.Fatalf("verified manifest = %+v", verified)
	}
	if strings.Contains(string(raw), "tenant-a") {
		t.Fatal("package leaked raw tenant id")
	}

	var pkg Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	var changedSignal map[string]any
	if err := json.Unmarshal(pkg.Attachments[0].Content, &changedSignal); err != nil {
		t.Fatal(err)
	}
	changedSignal["summary"] = "tampered but still valid JSON"
	pkg.Attachments[0].Content, _ = json.Marshal(changedSignal)
	tampered, _ := json.Marshal(pkg)
	if _, err := Verify(tampered); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("attachment tamper error = %v", err)
	}

	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	var changedManifest Manifest
	if err := json.Unmarshal(pkg.Manifest, &changedManifest); err != nil {
		t.Fatal(err)
	}
	changedManifest.PackageID = "pkg_tampered"
	pkg.Manifest, _ = json.Marshal(changedManifest)
	tampered, _ = json.Marshal(pkg)
	if _, err := Verify(tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("manifest tamper error = %v", err)
	}
}

func TestBuildRejectsUnredactedTenantDataAndUnknownStaysExplicit(t *testing.T) {
	now := time.Now().UTC()
	_, _, err := Build(BuildInput{TenantID: "tenant-a", Incident: incident.Incident{ID: "inc", TenantID: "tenant-a"}})
	if err == nil {
		t.Fatal("unredacted incident accepted")
	}
	manifest, _, err := Build(BuildInput{TenantID: "tenant-a", Incident: incident.Incident{ID: "inc", StartedAt: now, LastSeenAt: now}, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	last := manifest.Statements[len(manifest.Statements)-1]
	if last.Class != "unknown" || len(last.EvidenceIDs) != 0 {
		t.Fatalf("unknown conclusion = %+v", last)
	}
}
