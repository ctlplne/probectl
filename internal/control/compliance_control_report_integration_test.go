// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestComplianceControlReportSchedulesRetainPinnedTwoTenantEvidence(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	pin := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	native := newClientReportNativeProof(t, f, socket)
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	firstRun := time.Now().UTC().Add(2 * time.Minute)
	var views, artifacts, cookies [2]string
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{"metrics.write", permAuditRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			for range lane + 1 {
				if _, err := audit.TenantAppend(ctx, sc, "compliance-fixture", "configuration.updated", "private-fixture-target-"+strconv.Itoa(lane), nil); err != nil {
					return err
				}
			}
			return nil
		})
		cookies[lane] = auditorTestSession(t, f, tenant)
		format := []string{"csv", "pdf"}[lane]
		send := func(method, path string, value any, want int) []byte {
			return callComplianceControlReport(t, socket, cookies[lane], method, path, value, want)
		}
		input := reporting.DashboardCreateInput{Name: "Audit control lane " + strconv.Itoa(lane), Preset: "operator",
			Definition: reporting.DashboardDefinition{ComplianceControl: compliance.CMMCAuditControl, Provenance: []string{"tenant audit stream"},
				RedactionState: "sequence coverage", CoverageLimitations: []string{"retained audit stream"}}}
		var view store.DashboardView
		if err := json.Unmarshal(send(http.MethodPost, "/v1/dashboards", input, http.StatusCreated), &view); err != nil || view.ID == "" {
			t.Fatal("report configuration missing", err)
		}
		views[lane] = view.ID
		var schedule store.ReportSchedule
		request := reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Audit control daily", Format: format, Cadence: "daily", DestinationID: reportInboxDestination, FirstRunAt: firstRun}
		if err := json.Unmarshal(send(http.MethodPost, "/v1/dashboard-report-schedules", request, http.StatusCreated), &schedule); err != nil || schedule.ID == "" {
			t.Fatal("report schedule missing", err)
		}
		var expected audit.TenantVerificationCoverage
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			expected, err = audit.TenantVerifyWithCoverage(ctx, sc)
			return err
		})
		if err := supervisor.materializeTenantReports(t.Context(), tenant, firstRun.Add(time.Second)); err != nil {
			t.Fatal("tenant report schedule did not deliver", err)
		}
		var inbox struct {
			Items []reportArtifactView `json:"items"`
		}
		if err := json.Unmarshal(send(http.MethodGet, "/v1/dashboard-report-artifacts", nil, http.StatusOK), &inbox); err != nil || len(inbox.Items) != 1 ||
			inbox.Items[0].ScheduleID == nil || *inbox.Items[0].ScheduleID != schedule.ID {
			t.Fatal("exactly one scheduled tenant report was expected", err, len(inbox.Items))
		}
		artifacts[lane] = inbox.Items[0].ID
		body := send(http.MethodGet, "/v1/dashboard-report-artifacts/"+artifacts[lane], nil, http.StatusOK)
		proveComplianceControlReportBytes(t, body, format, pin, tenant, expected)
		proveComplianceControlReportTransports(t, native, tenant, f.tenants[1-lane], view.ID, artifacts[lane], body)
	}
	for lane, tenant := range f.tenants {
		path := "/v1/dashboard-report-artifacts/" + artifacts[1-lane]
		callComplianceControlReport(t, socket, cookies[lane], http.MethodGet, path, nil, http.StatusNotFound)
		checkComplianceControlBrowser(t, socket, cookies[lane], views[lane], lane)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permAuditRead)
			return err
		})
		restricted := auditorTestSession(t, f, tenant)
		path = "/v1/dashboard-report-artifacts/" + artifacts[lane]
		callComplianceControlReport(t, socket, restricted, http.MethodGet, path, nil, http.StatusNotFound)
		inbox := callComplianceControlReport(t, socket, restricted, http.MethodGet, "/v1/dashboard-report-artifacts", nil, http.StatusOK)
		if bytes.Contains(inbox, []byte(artifacts[lane])) {
			t.Fatal("withdrawn audit access disclosed signed report metadata")
		}
		if err := supervisor.materializeTenantReports(t.Context(), tenant, firstRun.Add(25*time.Hour)); err == nil {
			t.Fatal("the schedule ran after its owner's audit access was withdrawn")
		}
	}
}

func proveComplianceControlReportTransports(t *testing.T, proof *clientReportNativeProof, tenant, sibling, view, artifact string, expectedBytes []byte) {
	t.Helper()
	client := sdk.NewClient(proof.rest.URL, sdk.WithHTTPClient(proof.rest.Client()), sdk.WithToken(proof.fixture.tokens[tenant]))
	var stored bytes.Buffer
	if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact}, &stored, 1<<20); err != nil || !bytes.Equal(stored.Bytes(), expectedBytes) {
		t.Fatal("Go SDK did not download the exact signed scheduled output", err)
	}
	raw, code := proof.invokeCLI(tenant, nil, "dashboard", "export", view)
	var exported reporting.DashboardManifest
	if err := json.Unmarshal(raw, &exported); code != 0 || err != nil || exported.Spec.Definition.ComplianceControl != compliance.CMMCAuditControl {
		t.Fatal("CLI did not export the exact control selection", code, err)
	}
	if downloaded, code := proof.invokeCLI(tenant, nil, "dashboard-report", "download", artifact); code != 0 || !bytes.Equal(downloaded, expectedBytes) {
		t.Fatal("CLI did not download the exact signed scheduled output", code)
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		caller := reportMCPClient{t: t, socket: proof.native, foreignTenant: sibling, protocolVersion: wire}
		var dashboard mcp.ReportDashboard
		caller.call(proof.fixture.tokens[tenant], "report_dashboard", map[string]string{"id": view}, &dashboard, true, "native control selection unavailable")
		if dashboard.TenantID != tenant || dashboard.Definition.ComplianceControl != compliance.CMMCAuditControl {
			t.Fatal("native control selection crossed tenant scope")
		}
		stdio := openInterfaceRoleStdio(t, proof.server, proof.authenticator, proof.fixture.tokens[tenant], wire, time.Minute)
		var link mcp.ReportArtifactLink
		stdio.call(t, wire, "report_artifact_link", map[string]string{"id": artifact}, &link, true)
		if !link.AuthenticationRequired || link.Artifact.BodyBytes != int64(len(expectedBytes)) || link.Artifact.BodySHA256 != hex.EncodeToString(crypto.Hash(expectedBytes)) {
			t.Fatal("native scheduled artifact link changed stored bytes or current authorization")
		}
	}
}

func callComplianceControlReport(t *testing.T, socket *httptest.Server, cookie, method, path string, value any, status int) []byte {
	t.Helper()
	var body io.Reader
	if value != nil {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", socket.URL)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookie})
	res, err := socket.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != status {
		t.Fatalf("%s %s status %d, want %d: %v %s", method, path, res.StatusCode, status, err, raw)
	}
	return raw
}

func proveComplianceControlReportBytes(t *testing.T, body []byte, format, pin, tenant string, expected audit.TenantVerificationCoverage) {
	t.Helper()
	signed := complianceControlReportAttachment(t, body, format)
	file := filepath.Join(t.TempDir(), "compliance-control.json")
	if err := os.WriteFile(file, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, raw := verifiedAuditorBundleFile(t, file, pin, tenant)
	if manifest.Control == nil || manifest.Control.Reference != compliance.CMMCAuditControl || len(manifest.Sections) != 1 {
		t.Fatal("scheduled attachment changed the selected control")
	}
	if bytes.Contains(raw, []byte(tenant)) || bytes.Contains(raw, []byte("private-fixture-target")) {
		t.Fatal("scheduled attachment disclosed private audit payload")
	}
	var bundle compliance.AuditorPackage
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	assertAuditorAuditChainSection(t, manifest.Sections[0], bundle.Attachments, compliance.StatusVerified,
		[3]int64{expected.HeadSequence, expected.PrunedThrough, expected.RetainedEvents})
}

func complianceControlReportAttachment(t *testing.T, body []byte, format string) []byte {
	t.Helper()
	if format == "pdf" {
		match := regexp.MustCompile(`/Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size ([0-9]+) >> /Length ([0-9]+) >>\nstream\n`).FindSubmatchIndex(body)
		if match == nil {
			t.Fatal("PDF omitted its signed control evidence attachment")
		}
		length, err := strconv.Atoi(string(body[match[4]:match[5]]))
		if err != nil || length <= 0 || length > len(body)-match[1] {
			t.Fatal("PDF evidence attachment length is invalid")
		}
		return body[match[1] : match[1]+length]
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	var signed bytes.Buffer
	for ordinal := 0; ; {
		row, err := reader.Read()
		if err == io.EOF {
			return signed.Bytes()
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(row) != 6 || len(row[0]) != 32 || len(row[1]) != 64 {
			continue
		}
		chunk, err := base64.StdEncoding.DecodeString(row[5])
		if err != nil || row[3] != strconv.Itoa(ordinal) {
			t.Fatal("CSV evidence attachment chunks are incomplete or reordered")
		}
		signed.Write(chunk)
		ordinal++
	}
}

func checkComplianceControlBrowser(t *testing.T, socket *httptest.Server, cookie, view string, lane int) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "report-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, theme := range []string{"light", "dark"} {
		name := "Audit report configured in " + theme
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: socket.URL + "/ui/dashboards?view=" + view + "#saved-dashboard", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
			TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
			Expect: []string{"Audit control lane " + strconv.Itoa(lane), "Build CMMC audit evidence", "Signed verification of the retained probectl audit stream"},
			Absent: []string{"Audit control lane " + strconv.Itoa(1-lane)},
			Steps: []testsupport.RenderStep{
				{Click: "Build CMMC audit evidence (" + compliance.CMMCAuditControl + ")", Role: "checkbox", Within: "#saved-dashboard"},
				{Fill: `#saved-dashboard label:text-is("Dashboard name") + div input`, Value: name},
				{Click: "Save dashboard", Within: "#saved-dashboard", Expect: []string{"Dashboard saved", name}},
			},
		})
	}
}
