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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type realFlowControlExpectation struct {
	control, zone, status string
}

// The caller has already proved the exact owned raw softflowd observations.
// Each pack selects the same supported collector path and owner scope.
func proveRealFlowComplianceReports(t *testing.T, st *shipped.Stack, own, sibling edgeFlowRegistration, link roleRouterLink, interfaces [2]string, pin string) {
	t.Helper()
	registrations := [2]edgeFlowRegistration{own, sibling}
	directional := [2]realFlowControlExpectation{
		{compliance.PCIInboundNetworkControl, "adjacent", compliance.StatusFailed},
		{compliance.PCIOutboundNetworkControl, "router", compliance.StatusObserved},
	}
	proveRealFlowControlPair(t, st, registrations, interfaces, link, pin, directional)
	t.Run("live-boundary-and-monitoring", func(t *testing.T) {
		for _, primary := range []realFlowControlExpectation{
			{compliance.PCISegmentationControl, "", compliance.StatusFailed},
			{compliance.CMMCBoundaryControl, "", compliance.StatusFailed},
			{compliance.CMMCMonitoringControl, "", compliance.StatusObserved},
		} {
			t.Run(primary.control, func(t *testing.T) {
				pair := [2]realFlowControlExpectation{primary, {control: primary.control, status: compliance.StatusObserved}}
				proveRealFlowControlPair(t, st, registrations, interfaces, link, pin, pair)
			})
		}
	})
}

func proveRealFlowControlPair(t *testing.T, st *shipped.Stack, registrations [2]edgeFlowRegistration, interfaces [2]string,
	link roleRouterLink, pin string, expected [2]realFlowControlExpectation) {
	t.Helper()
	schedules := [2]string{}
	ids := [2]string{}
	policies := [2]string{}
	for lane, registration := range registrations {
		if expected[lane].control != compliance.CMMCMonitoringControl {
			policies[lane] = realFlowCompliancePolicy(link.routerIP, link.peerIP, lane != 0)
		}
		schedules[lane] = scheduleRealFlowComplianceCSV(t, st, registration, interfaces[lane], policies[lane], expected[lane])
	}
	var sourceDigests [2]string
	for lane, registration := range registrations {
		id, raw := awaitRealFlowComplianceCSV(t, st, registration, schedules[lane])
		ids[lane] = id
		sourceDigests[lane] = verifyRealFlowControlCSV(t, raw, registration.tenantID, pin, policies[lane], expected[lane])
	}
	if sourceDigests[0] == sourceDigests[1] {
		t.Fatal("the reports reused another tenant's selected sources")
	}
	for lane, registration := range registrations {
		status, _ := st.Do(t, registration.cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+ids[1-lane], nil)
		if status != http.StatusNotFound {
			t.Fatal("sibling artifact ID crossed the tenant boundary", status)
		}
	}
	t.Logf("verified scheduled signed control reports %s and %s from original flow observations", expected[0].control, expected[1].control)
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
	return strings.TrimSpace(fmt.Sprintf(`name: lab-boundary
zones:
  - name: router
    cidrs: [%q]
  - name: adjacent
    cidrs: [%q]
rules:
  - id: selected-boundary
    from: router
    to: adjacent%s
`, sourceNetwork.String(), destinationNetwork.String(), portRule))
}

func scheduleRealFlowComplianceCSV(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, measurementID, policy string,
	expected realFlowControlExpectation) string {
	t.Helper()
	input := reporting.DashboardCreateInput{
		Name: "Owned control " + expected.control, Preset: "operator",
		Definition: reporting.DashboardDefinition{
			ComplianceControl: expected.control,
			ComplianceFlow: &reporting.ComplianceFlowDefinition{Lookback: "15m", Policy: policy,
				ProtectedZone: expected.zone,
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
		DashboardID: view.ID, Name: "Owned control " + expected.control, Format: "csv", Cadence: "daily",
		DestinationID: "tenant-report-inbox", FirstRunAt: time.Now().UTC(),
	})
	if err := json.Unmarshal(raw, &schedule); status != http.StatusCreated || err != nil || schedule.ID == "" {
		t.Fatal("the shipped tenant could not schedule its control report", expected.control, status, err)
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

func verifyRealFlowControlCSV(t *testing.T, raw []byte, tenant, pin, policy string, expected realFlowControlExpectation) string {
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
	if err != nil || manifest.TenantScopeDigest != wantScope || manifest.Control == nil ||
		manifest.Control.Reference != expected.control || manifest.Control.ProtectedZone != expected.zone || manifest.Control.Window == nil ||
		manifest.Control.Window.To.Sub(manifest.Control.Window.From) != 15*time.Minute ||
		len(manifest.Sections) != 1 || manifest.Sections[0].Status != expected.status ||
		manifest.Sections[0].Kind != compliance.ControlEvidenceSection(expected.control) {
		t.Fatal("shipped evidence changed the signed scope or observed disposition", expected.control, err)
	}
	var pkg compliance.AuditorPackage
	if err := json.Unmarshal(signed.Bytes(), &pkg); err != nil || pkg.Signing.Fingerprint != pin || len(pkg.Attachments) != 1 {
		t.Fatal("shipped package did not match the independent operator pin", err)
	}
	var original struct {
		SelectedPoints     int                  `json:"selected_points"`
		CurrentPoints      int                  `json:"points_with_current_sources"`
		RetainedRows       int                  `json:"retained_rows"`
		AttestedRows       int                  `json:"attested_rows"`
		FirstObserved      time.Time            `json:"first_observed"`
		LastObserved       time.Time            `json:"last_observed"`
		SelectedSources    string               `json:"selected_sources_sha256"`
		OriginalDigest     string               `json:"capture_owners_sha256"`
		ObservationsDigest string               `json:"observations_sha256"`
		PolicyDigest       string               `json:"policy_sha256"`
		Segmentation       *compliance.Evidence `json:"segmentation"`
	}
	if err := json.Unmarshal(pkg.Attachments[0].Content, &original); err != nil || original.AttestedRows <= 0 || original.AttestedRows > original.RetainedRows ||
		original.SelectedPoints != 1 || original.CurrentPoints != 1 || original.FirstObserved.IsZero() ||
		original.FirstObserved.Before(manifest.Control.Window.From) || original.LastObserved.Before(original.FirstObserved) ||
		!original.LastObserved.Before(manifest.Control.Window.To) || len(original.SelectedSources) != 64 ||
		len(original.OriginalDigest) != 64 || len(original.ObservationsDigest) != 64 {
		t.Fatal("shipped control did not cite original current flow evidence", expected.control, err)
	}
	if expected.control == compliance.CMMCMonitoringControl {
		if original.Segmentation != nil || original.PolicyDigest != "" {
			t.Fatal("a flow coverage report included an unselected segmentation policy")
		}
		return original.SelectedSources
	}
	if original.PolicyDigest != hex.EncodeToString(crypto.Hash([]byte(policy))) || original.Segmentation == nil ||
		original.Segmentation.Tenant != "" || compliance.VerifyEvidence(*original.Segmentation) != nil ||
		len(original.Segmentation.Records) != 1 || original.Segmentation.Records[0].Result.ObservedPairs == 0 {
		t.Fatal("shipped control lost its exact policy and original case", expected.control)
	}
	return original.SelectedSources
}
