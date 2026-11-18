// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The caller has already proved the exact owned raw softflowd observations.
// Both control packs use the same supported collector path and owner scope.
func proveRealFlowComplianceReports(t *testing.T, st *shipped.Stack, own, sibling edgeFlowRegistration, link roleRouterLink, interfaces [2]string, pin string) {
	t.Helper()
	registrations := [2]edgeFlowRegistration{own, sibling}
	schedules := [2]string{}
	ids := [2]string{}
	for lane, registration := range registrations {
		policy := realFlowCompliancePolicy(link.routerIP, link.peerIP, lane != 0)
		schedules[lane] = scheduleRealFlowComplianceCSV(t, st, registration, interfaces[lane], policy, lane)
	}
	for lane, registration := range registrations {
		id, raw := awaitRealFlowComplianceCSV(t, st, registration, schedules[lane])
		ids[lane] = id
		verifyRealFlowControlCSV(t, raw, registration.tenantID, pin, lane)
	}
	for lane, registration := range registrations {
		status, _ := st.Do(t, registration.cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+ids[1-lane], nil)
		if status != http.StatusNotFound {
			t.Fatal("sibling artifact ID crossed the tenant boundary", status)
		}
	}
}

func realFlowCompliancePolicy(source, destination string, clean bool) string {
	_, sourceNetwork, _ := net.ParseCIDR(source + "/32")
	_, destinationNetwork, _ := net.ParseCIDR(destination + "/32")
	portRule := ""
	if clean {
		// The fixture produces ordinary ICMP with no application destination
		// port. Measuring it supplies zone-pair coverage for this port rule.
		portRule = "\n    ports: [443]"
	}
	return fmt.Sprintf(`name: lab-boundary
zones:
  - name: router
    cidrs: [%q]
  - name: adjacent
    cidrs: [%q]
rules:
  - id: selected-boundary
    from: router
    to: adjacent%s
`, sourceNetwork.String(), destinationNetwork.String(), portRule)
}

func scheduleRealFlowComplianceCSV(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, measurementID, policy string, lane int) string {
	t.Helper()
	input := reporting.DashboardCreateInput{
		Name: fmt.Sprintf("Owned captured boundary %d", lane), Preset: "operator",
		Definition: reporting.DashboardDefinition{
			ComplianceControl: []string{compliance.PCIInboundNetworkControl, compliance.PCIOutboundNetworkControl}[lane],
			ComplianceFlow: &reporting.ComplianceFlowDefinition{Lookback: "15m", Policy: policy,
				ProtectedZone: []string{"adjacent", "router"}[lane],
				Sources:       []reporting.ComplianceFlowSource{{ContextID: reg.contextID, EntityID: measurementID}}},
			Provenance: []string{"Pinned lab IPFIX from the owning collector"}, RedactionState: "selected network evidence",
			CoverageLimitations: []string{"observed source and bounded window"},
		},
	}
	var view struct{ ID string }
	status, raw := st.Do(t, reg.cookie, http.MethodPost, "/v1/dashboards", input)
	if err := json.Unmarshal(raw, &view); status != http.StatusCreated || err != nil || view.ID == "" {
		t.Fatal("the shipped tenant could not save its control definition", status, err)
	}
	var schedule struct{ ID string }
	status, raw = st.Do(t, reg.cookie, http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{
		DashboardID: view.ID, Name: "Owned directional evidence", Format: "csv", Cadence: "daily",
		DestinationID: "tenant-report-inbox", FirstRunAt: time.Now().UTC(),
	})
	if err := json.Unmarshal(raw, &schedule); status != http.StatusCreated || err != nil || schedule.ID == "" {
		t.Fatal("the shipped tenant could not schedule its directional report", status, err)
	}
	return schedule.ID
}

func awaitRealFlowComplianceCSV(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, schedule string) (string, []byte) {
	t.Helper()
	var artifact string
	shipped.Await(t, "scheduled signed report from original captured IPFIX", 90*time.Second, func() bool {
		status, raw := st.Do(t, reg.cookie, http.MethodGet, "/v1/dashboard-report-artifacts", nil)
		var inbox struct {
			Items []struct {
				ID         string `json:"id"`
				ScheduleID string `json:"schedule_id"`
			}
		}
		if status != http.StatusOK || json.Unmarshal(raw, &inbox) != nil {
			return false
		}
		for _, item := range inbox.Items {
			if item.ScheduleID == schedule && item.ID != "" {
				artifact = item.ID
				return true
			}
		}
		return false
	})
	status, raw := st.Do(t, reg.cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifact, nil)
	if status != http.StatusOK || len(raw) == 0 {
		t.Fatal("own signed control CSV unavailable", status)
	}
	return artifact, raw
}

func verifyRealFlowControlCSV(t *testing.T, raw []byte, tenant, pin string, lane int) {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	var signed bytes.Buffer
	for ordinal := 0; ; {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(row) != 6 || len(row[0]) != 32 || len(row[1]) != 64 {
			continue
		}
		chunk, err := base64.StdEncoding.DecodeString(row[5])
		if err != nil || row[3] != strconv.Itoa(ordinal) {
			t.Fatal("shipped CSV returned an incomplete signed attachment", err)
		}
		signed.Write(chunk)
		ordinal++
	}
	manifest, err := compliance.VerifyEvidenceBundle(signed.Bytes())
	wantScope := hex.EncodeToString(crypto.Hash([]byte("probectl-auditor-scope/v1|" + tenant)))
	wantStatus := []string{compliance.StatusFailed, compliance.StatusObserved}[lane]
	if err != nil || manifest.TenantScopeDigest != wantScope || manifest.Control == nil ||
		manifest.Control.Reference != []string{compliance.PCIInboundNetworkControl, compliance.PCIOutboundNetworkControl}[lane] ||
		manifest.Control.ProtectedZone != []string{"adjacent", "router"}[lane] || manifest.Control.Window == nil ||
		manifest.Control.Window.To.Sub(manifest.Control.Window.From) != 15*time.Minute ||
		len(manifest.Sections) != 1 || manifest.Sections[0].Status != wantStatus {
		t.Fatal("shipped evidence changed the signed scope or observed disposition", err)
	}
	var pkg compliance.AuditorPackage
	if err := json.Unmarshal(signed.Bytes(), &pkg); err != nil || pkg.Signing.Fingerprint != pin || len(pkg.Attachments) != 1 {
		t.Fatal("shipped package did not match the independent operator pin", err)
	}
	var original struct {
		AttestedRows       int                  `json:"attested_rows"`
		OriginalDigest     string               `json:"capture_owners_sha256"`
		ObservationsDigest string               `json:"observations_sha256"`
		Segmentation       *compliance.Evidence `json:"segmentation"`
	}
	if err := json.Unmarshal(pkg.Attachments[0].Content, &original); err != nil || original.AttestedRows <= 0 ||
		len(original.OriginalDigest) != 64 || len(original.ObservationsDigest) != 64 || original.Segmentation == nil ||
		len(original.Segmentation.Records) != 1 || original.Segmentation.Records[0].Result.ObservedPairs == 0 {
		t.Fatal("shipped control did not cite original current flow evidence", err)
	}
}
