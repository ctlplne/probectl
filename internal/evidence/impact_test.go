// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestSignedImpactKeepsCompleteCapturePopulationExactCountersAndTenantBinding(t *testing.T) {
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	impact := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: "impact-incident", Preview: true, EvaluatedAt: at,
		Current:  incident.ImpactPeriod{From: at.Add(-time.Minute), To: at, Coverage: "observed_attested_records", AttestedRecords: 50_001, ObservedTotals: &incident.ImpactCounters{RawBytes: "18446744073709551615", RawPackets: "7", ScaledBytes: "55340232221128654845", ScaledPackets: "21"}, Captures: []incident.ImpactCaptureCitation{}},
		Previous: incident.ImpactPeriod{From: at.Add(-7*24*time.Hour - time.Minute), To: at.Add(-7 * 24 * time.Hour), Coverage: "no_observed_records", Captures: []incident.ImpactCaptureCitation{}},
		Members:  []incident.ImpactMember{}, UnresolvedSignalIDs: []string{}, Customers: []incident.ImpactCustomer{}, CustomerCoverage: "not_evaluated", Interpretation: "Observed measurement points with unavailable baseline."}
	for i := range 50_001 {
		impact.Current.Captures = append(impact.Current.Captures, incident.ImpactCaptureCitation{Key: fmt.Sprintf("%064x", i+1), CapturedAt: at.Add(-time.Second), ContextID: "owned-context", RouterID: "owned-router", OriginalSourceID: "evidence/original", CurrentSourceID: "evidence/current"})
	}
	var scope string
	for _, tenant := range []string{"signed-impact-tenant-red", "signed-impact-tenant-blue"} {
		manifest, attachments, err := Build(BuildInput{TenantID: tenant, Incident: incident.Incident{ID: impact.IncidentID}, CreatedAt: at, Impact: &impact})
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Evidence) != 1 || manifest.Evidence[0].Kind != "incident.impact" || len(manifest.Evidence[0].Provenance.MissingIntervals) != 1 || manifest.Evidence[0].Provenance.MissingIntervals[0].Reason != "no_observed_records" {
			t.Fatal("impact export lost explicit coverage", manifest)
		}
		body, err := Sign(manifest, attachments, key)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), tenant) || scope == verified.TenantScopeDigest {
			t.Fatal("signed impact lost its independent tenant-scope binding")
		}
		scope = verified.TenantScopeDigest
		var pkg Package
		if err := json.Unmarshal(body, &pkg); err != nil {
			t.Fatal(err)
		}
		var retained incident.ImpactResponse
		if err := json.Unmarshal(pkg.Attachments[0].Content, &retained); err != nil {
			t.Fatal(err)
		}
		if len(retained.Current.Captures) != 50_001 || retained.Current.Captures[50_000].Key != impact.Current.Captures[50_000].Key || retained.Current.ObservedTotals.ScaledBytes != "55340232221128654845" || retained.Previous.ObservedTotals != nil {
			t.Fatal("signed impact truncated captures, rounded counters or manufactured baseline zero")
		}
		retained.Current.Captures[50_000].CurrentSourceID = "substituted-source"
		pkg.Attachments[0].Content, err = json.Marshal(retained)
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(mutated); err == nil {
			t.Fatal("a late capture provenance substitution escaped offline verification")
		}
	}
	manifest, _, err := Build(BuildInput{TenantID: "signed-impact-tenant-red", Incident: incident.Incident{ID: impact.IncidentID}, CreatedAt: at, Impact: &impact, Conclusion: "A model conclusion without signal evidence.", Grounded: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range manifest.Statements {
		if statement.ID == "conclusion" && (statement.Class != "unknown" || len(statement.EvidenceIDs) != 0) {
			t.Fatal("later impact evidence laundered an unseen RCA conclusion", statement)
		}
	}
	impact.IncidentID = "foreign-incident"
	if _, _, err := Build(BuildInput{TenantID: "signed-impact-tenant-red", Incident: incident.Incident{ID: "impact-incident"}, CreatedAt: at, Impact: &impact}); err == nil {
		t.Fatal("an impact for another incident entered the signed package")
	}
}
