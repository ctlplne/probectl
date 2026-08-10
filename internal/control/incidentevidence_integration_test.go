// SPDX-License-Identifier: MPL-2.0

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

func TestGoldenIntermittentISPExportIsOneTenantScopedVerifiableIncident(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	privatePEM, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	srv.WithEvidenceSigningKey(privatePEM)
	h := srv.Handler()
	ctx := context.Background()
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("evidence-a-%d", time.Now().UnixNano()), "Evidence A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("evidence-b-%d", time.Now().UnixNano()), "Evidence B")
	if err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC().Truncate(time.Second)
	target := "198.51.100.17"
	correlator := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	var exportedIncident *incident.Incident
	for _, vantage := range []string{"branch-east", "branch-central", "branch-west"} {
		for offset := -45; offset <= 45; offset += 5 {
			state := "observed"
			kind := "path.healthy"
			title := "Terminal response observed before or after the fault"
			summary := "End-to-end reachability present; intermediate ICMP behavior is not treated as terminal loss"
			severity := incident.SeverityInfo
			if offset >= -15 && offset <= 15 {
				kind = "path.terminal_loss"
				title = "Terminal loss observed in the injected ISP domain"
				summary = "Destination response absent while intermediate ICMP behavior remains non-conclusive"
				severity = incident.SeverityCritical
			}
			if vantage == "branch-west" && offset == 0 {
				state = "unknown"
				kind = "path.intermediate_icmp_unknown"
				title = "Intermediate ICMP response is contrary but non-conclusive"
				summary = "A router response neither proves nor disproves terminal forwarding"
				severity = incident.SeverityWarning
			}
			sig := incident.Signal{
				TenantID: tenantA.ID, Plane: "network", Kind: kind, Severity: severity,
				Title: title, Summary: summary, Target: target, OccurredAt: base.Add(time.Duration(offset) * time.Second),
				Attributes: map[string]string{
					"evidence.source": "customer-synthetic", "evidence.state": state,
					"vantage_id": vantage, "vantage_owner": "customer-owned",
					"trust_tier": "tenant-mtls", "independence": "independent-site",
					"sample_cadence_seconds": "5", "clock_quality": "ntp-skew-under-2s",
					"freshness": "current-at-capture", "missing_intervals": "[]",
					"fault_domain": "isp",
				},
			}
			exportedIncident, err = correlator.Ingest(ctx, sig)
			if err != nil {
				t.Fatalf("ingest %s offset %d: %v", vantage, offset, err)
			}
		}
	}
	foreign, err := correlator.Ingest(ctx, incident.Signal{
		TenantID: tenantB.ID, Plane: "network", Kind: "path.healthy", Severity: incident.SeverityInfo,
		Title: "tenant B only marker", Target: target, OccurredAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.ID == exportedIncident.ID {
		t.Fatal("cross-tenant signals correlated into one incident")
	}

	list := apiReq(t, h, http.MethodGet, "/v1/incidents", tenantA.ID, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body)
	}
	var listed struct {
		Items []incident.Incident `json:"items"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("golden fault produced %d incidents, want exactly one", len(listed.Items))
	}

	exported := apiReq(t, h, http.MethodPost, "/v1/incidents/"+exportedIncident.ID+"/exports", tenantA.ID, nil)
	if exported.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exported.Code, exported.Body)
	}
	manifest, err := evidence.Verify(exported.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(manifest.Evidence), 57; got != want {
		t.Fatalf("evidence records=%d want=%d", got, want)
	}
	if manifest.Window.To.Sub(manifest.Window.From) != 90*time.Second {
		t.Fatalf("window=%s want=90s", manifest.Window.To.Sub(manifest.Window.From))
	}
	vantages := map[string]int{}
	unknown := 0
	for _, record := range manifest.Evidence {
		vantages[record.Provenance.VantageID]++
		if record.State == evidence.StateUnknown {
			unknown++
		}
		if record.Provenance.VantageOwner != "customer-owned" || record.Provenance.SampleCadenceSeconds != 5 ||
			record.Provenance.ClockQuality != "ntp-skew-under-2s" {
			t.Fatalf("mandatory provenance lost: %+v", record.Provenance)
		}
	}
	if len(vantages) != 3 || unknown != 1 {
		t.Fatalf("vantages=%v unknown=%d", vantages, unknown)
	}
	body := exported.Body.String()
	if strings.Contains(body, tenantA.ID) || strings.Contains(body, tenantB.ID) || strings.Contains(body, "tenant B only marker") {
		t.Fatal("export leaked raw tenant scope or foreign evidence")
	}

	foreignRead := apiReq(t, h, http.MethodPost, "/v1/incidents/"+exportedIncident.ID+"/exports", tenantB.ID, nil)
	missingRead := apiReq(t, h, http.MethodPost, "/v1/incidents/00000000-0000-4000-8000-000000000099/exports", tenantB.ID, nil)
	var foreignErr, missingErr errorBody
	mustJSON(t, foreignRead, &foreignErr)
	mustJSON(t, missingRead, &missingErr)
	if foreignRead.Code != http.StatusNotFound || missingRead.Code != http.StatusNotFound ||
		foreignErr.Error.Code != missingErr.Error.Code || foreignErr.Error.Message != missingErr.Error.Message ||
		foreignErr.Error.RequestID == "" || missingErr.Error.RequestID == "" {
		t.Fatalf("cross-tenant and missing export differ: foreign=%d %s missing=%d %s",
			foreignRead.Code, foreignRead.Body, missingRead.Code, missingRead.Body)
	}
}
