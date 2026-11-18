// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestDirectionalPCIReportsKeepSelectedZoneAndTenant(t *testing.T) {
	f, _ := seedIncidentImpactFlowFixture(t)
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private)
	pin := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	native := newClientReportNativeProof(t, f, socket)
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	firstRun := time.Now().UTC().Add(time.Minute)
	var viewIDs, artifacts, cookies [2]string
	const zone = "local-customer-cde"
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{"metrics.write", permAuditRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		cookies[lane] = auditorTestSession(t, f, tenant)
		send := func(method, path string, value any, status int) []byte {
			return callComplianceControlReport(t, socket, cookies[lane], method, path, value, status)
		}
		control := []string{compliance.PCIInboundNetworkControl, compliance.PCIOutboundNetworkControl}[lane]
		format := []string{"csv", "pdf"}[lane]
		// Both actual source receipts describe .1 to .2. Each tenant chooses
		// which endpoint is its CDE and retains its own existing source port.
		from, to := []string{"outside", zone}[lane], []string{zone, "outside"}[lane]
		policy := fmt.Sprintf(directionalPCIFixturePolicy, from, to, from, to)
		source := reporting.ComplianceFlowSource{ContextID: f.contextID, EntityID: f.routerID}
		flow := reporting.ComplianceFlowDefinition{Lookback: "24h", Sources: []reporting.ComplianceFlowSource{source}, Policy: policy}
		input := reporting.DashboardCreateInput{Name: "Directional control lane " + strconv.Itoa(lane), Preset: "operator", Shared: true,
			Definition: reporting.DashboardDefinition{ComplianceControl: control, ComplianceFlow: &flow,
				RedactionState: "selected directional flows", Provenance: []string{"original receipt model"}, CoverageLimitations: []string{"selected sources and window"}}}
		send(http.MethodPost, "/v1/dashboards", input, http.StatusUnprocessableEntity)
		flow.ProtectedZone = "undeclared-zone"
		send(http.MethodPost, "/v1/dashboards", input, http.StatusUnprocessableEntity)
		flow.ProtectedZone = zone
		var view store.DashboardView
		if err := json.Unmarshal(send(http.MethodPost, "/v1/dashboards", input, http.StatusCreated), &view); err != nil || view.ID == "" {
			t.Fatal("authoritative directional dashboard unavailable", err)
		}
		viewIDs[lane] = view.ID
		request := proveComplianceFlowManifest(t, send, view.ID, source, policy, zone)
		proveComplianceFlowManifestTransports(t, native, tenant, f.tenants[1-lane], request)
		send(http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Directional control daily",
			Format: format, Cadence: "daily", DestinationID: reportInboxDestination, FirstRunAt: firstRun}, http.StatusCreated)
		if err := supervisor.materializeTenantReports(t.Context(), tenant, firstRun.Add(time.Second)); err != nil {
			t.Fatal("directional report did not materialize", err)
		}
		var inbox struct{ Items []reportArtifactView }
		if err := json.Unmarshal(send(http.MethodGet, "/v1/dashboard-report-artifacts", nil, http.StatusOK), &inbox); err != nil ||
			len(inbox.Items) != 1 || inbox.Items[0].ScheduleID == nil {
			t.Fatal("only the scheduled directional report should be retained", err, len(inbox.Items))
		}
		artifact := inbox.Items[0]
		artifacts[lane] = artifact.ID
		body := send(http.MethodGet, "/v1/dashboard-report-artifacts/"+artifact.ID, nil, http.StatusOK)
		status := []string{compliance.StatusFailed, compliance.StatusObserved}[lane]
		proveDirectionalPCIReportBytes(t, body, format, pin, tenant, control, zone, from, to, status)
		proveComplianceControlReportTransports(t, native, tenant, f.tenants[1-lane], view.ID, artifact.ID, control, body)
		checkDirectionalPCIBrowser(t, socket, cookies[lane], f.contextID, f.routerID, view.ID, control, zone, policy, lane)
	}
	proveComplianceFlowContextDenial(t, f, socket, native, cookies, viewIDs, artifacts)
	for lane := range f.tenants {
		callComplianceControlReport(t, socket, cookies[lane], http.MethodGet, "/v1/dashboards/"+viewIDs[1-lane]+"/manifest", nil, http.StatusNotFound)
		callComplianceControlReport(t, socket, cookies[lane], http.MethodGet, "/v1/dashboard-report-artifacts/"+artifacts[1-lane], nil, http.StatusNotFound)
	}
}

const directionalPCIFixturePolicy = `name: declared-directional-boundary
zones:
  - name: %s
    cidrs: ["203.0.113.1/32"]
  - name: %s
    cidrs: ["203.0.113.2/32"]
rules:
  - id: forbidden-443
    from: %s
    to: %s
    bidirectional: true
    ports: [443]
`

func proveDirectionalPCIReportBytes(t *testing.T, body []byte, format, pin, tenant, reference, zone, from, to, status string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "directional-control.json")
	if err := os.WriteFile(path, complianceControlReportAttachment(t, body, format), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, raw := verifiedAuditorBundleFile(t, path, pin, tenant)
	if manifest.Control == nil || manifest.Control.Reference != reference || manifest.Control.ProtectedZone != zone ||
		manifest.Control.Window == nil || len(manifest.Sections) != 1 || manifest.Sections[0].Status != status {
		t.Fatal("signed directional control lost its exact zone, reference or verdict", manifest.Control)
	}
	var bundle compliance.AuditorPackage
	if err := json.Unmarshal(raw, &bundle); err != nil || len(bundle.Attachments) != 1 {
		t.Fatal("signed directional coverage missing", err)
	}
	var evidence complianceFlowEvidence
	if err := json.Unmarshal(bundle.Attachments[0].Content, &evidence); err != nil || evidence.AttestedRows != 1 ||
		evidence.Segmentation == nil || len(evidence.Segmentation.Records) != 1 {
		t.Fatal("signed directional evidence lost its one current flow and rule", err)
	}
	rule := evidence.Segmentation.Records[0].Result
	if rule.From != from || rule.To != to || rule.ObservedPairs != 1 || (rule.Violations == 1) != (status == compliance.StatusFailed) {
		t.Fatal("signed rule cited the wrong direction", rule)
	}
}

func checkDirectionalPCIBrowser(t *testing.T, socket *httptest.Server, cookie, contextID, entityID, view, control, zone, policy string, lane int) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "directional-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, theme := range []string{"light", "dark"} {
		name := "Directional report configured in " + theme
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: socket.URL + "/ui/dashboards?view=" + view + "#saved-dashboard", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
			TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
			Expect: []string{"Directional control lane " + strconv.Itoa(lane)}, Absent: []string{"Directional control lane " + strconv.Itoa(1-lane)},
			Steps: []testsupport.RenderStep{
				{Click: "Build flow control evidence", Role: "checkbox", Within: "#saved-dashboard"},
				{Select: "[aria-label='Flow control evidence configuration'] select", Value: control},
				{Fill: `#saved-dashboard label:text-is("Measurement point 1 routing context ID") + div input`, Value: contextID},
				{Fill: `#saved-dashboard label:text-is("Measurement point 1 device or interface ID") + div input`, Value: entityID},
				{Fill: `#saved-dashboard label:text-is("Cardholder-data zone") + div input`, Value: zone},
				{Fill: `#saved-dashboard label:text-is("Segmentation policy YAML") + div textarea`, Value: policy},
				{Fill: `#saved-dashboard label:text-is("Dashboard name") + div input`, Value: name},
				{Click: "Save dashboard", Within: "#saved-dashboard", Expect: []string{"Dashboard saved", name}},
			},
		})
	}
}
