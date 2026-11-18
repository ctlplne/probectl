// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestProviderComplianceReportsRequireTenantConsentAndKeepCountsPrivate(t *testing.T) {
	proveProviderComplianceReportQueue(t, false)
}

func TestProviderComplianceReportsServeCurrentBothThemes(t *testing.T) {
	proveProviderComplianceReportQueue(t, true)
}

func proveProviderComplianceReportQueue(t *testing.T, render bool) {
	t.Helper()
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	s := newSepStack(t, func(core *control.Server) {
		core.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)).WithEvidenceSigningKey(private)
	})
	admin := s.seedAdminOperator(t)
	op := s.createOperator(t, admin, RoleOperator)
	unique := strings.ReplaceAll(s.suffix, ".", "-")
	alpha := s.provisionTenant(t, admin, "compliance-a-"+unique)
	beta := s.provisionTenant(t, admin, "compliance-b-"+unique)
	users := []*sepTenantUser{s.tenantAdmin(t, alpha, "control-a-"+s.suffix+"@example.test"), s.tenantAdmin(t, beta, "control-b-"+s.suffix+"@example.test")}
	socket := httptest.NewTLSServer(s.h)
	t.Cleanup(socket.Close)
	call := func(cookie *http.Cookie, method, path string, input any, want int) []byte {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s: got %d, want %d: %.450s (%v)", method, path, response.StatusCode, want, raw, err)
		}
		return raw
	}
	const name = "Tenant owned CMMC evidence"
	schedules := make([]store.ReportSchedule, 2)
	for lane, user := range users {
		var view store.DashboardView
		dashboard := reporting.DashboardCreateInput{Name: name, Preset: "operator", Definition: reporting.DashboardDefinition{
			ComplianceControl: compliance.CMMCAuditControl, RedactionState: "retained audit coverage", Provenance: []string{"tenant audit chain"}, CoverageLimitations: []string{"selected retained stream"},
		}}
		sepJSON(t, call(user.cookie, http.MethodPost, "/v1/dashboards", dashboard, http.StatusCreated), &view)
		format := []string{"csv", "pdf"}[lane]
		input := reporting.ReportScheduleInput{DashboardID: view.ID, Name: name, Format: format, Cadence: "daily", DestinationID: "tenant-report-inbox", FirstRunAt: time.Now().UTC().Add(2 * time.Hour)}
		sepJSON(t, call(user.cookie, http.MethodPost, "/v1/dashboard-report-schedules", input, http.StatusCreated), &schedules[lane])
	}
	provider := &http.Cookie{Name: SessionCookie, Value: op.token}
	consent := func(lane int, optIn bool) {
		t.Helper()
		call(users[lane].cookie, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedules[lane].ID,
			map[string]bool{"provider_trigger_allowed": optIn}, http.StatusOK)
	}
	newRequest := func() string {
		t.Helper()
		value, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	queue := func(tenant, id string) reporting.ProviderReportQueueResult {
		t.Helper()
		var result reporting.ProviderReportQueueResult
		var fields map[string]json.RawMessage
		path := "/provider/v1/tenants/" + tenant + "/compliance-reports"
		raw := call(provider, http.MethodPost, path, map[string]string{"request_id": id}, http.StatusAccepted)
		sepJSON(t, raw, &result)
		sepJSON(t, raw, &fields)
		if len(fields) != 7 || result.TenantID != tenant || bytes.Contains(raw, []byte(name)) || bytes.Contains(raw, []byte(compliance.CMMCAuditControl)) {
			t.Fatal("provider received tenant report data rather than operation counts")
		}
		return result
	}
	progress := func(tenant, id string) reporting.ProviderReportQueueResult {
		t.Helper()
		var result reporting.ProviderReportQueueResult
		sepJSON(t, call(provider, http.MethodGet, "/provider/v1/tenants/"+tenant+"/compliance-reports/"+id, nil, http.StatusOK), &result)
		return result
	}
	consent(0, true)
	requestID := newRequest()
	call(users[0].cookie, http.MethodPost, "/provider/v1/tenants/"+alpha+"/compliance-reports",
		map[string]string{"request_id": requestID}, http.StatusUnauthorized)
	if render {
		var inventory struct{ Items []Tenant }
		sepJSON(t, call(provider, http.MethodGet, "/provider/v1/tenants", nil, http.StatusOK), &inventory)
		checkProviderComplianceReportWorkflow(t, socket, provider, inventory.Items, [2]string{alpha, beta})
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(alpha)), s.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT provider_request_id::text FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, alpha, schedules[0].ID).Scan(&requestID)
		}); err != nil || requestID == "" {
			t.Fatal("rendered provider queue did not retain the exact owned request", err)
		}
	} else if got := queue(alpha, requestID); got.Eligible != 1 || got.Queued != 1 || got.Pending != 1 || got.Replay {
		t.Fatal("authoritative opted-in schedule was not queued", got)
	}
	if got := queue(beta, requestID); got.Eligible != 0 || got.Queued != 0 || got.Pending != 0 {
		t.Fatal("provider advanced an unconsented sibling schedule", got)
	}
	if got := queue(alpha, requestID); !got.Replay || got.Queued != 1 {
		t.Fatal("request retry did not reuse its immutable receipt", got)
	}
	call(provider, http.MethodGet, "/provider/v1/tenants/"+alpha+"/monthly-reports/"+requestID, nil, http.StatusNotFound)
	worker, ok := control.BuildDashboardReportSupervisor(s.db.Pool(), time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok {
		t.Fatal("tenant report worker unavailable")
	}
	worker.WithReportSources(s.srv).Tick(t.Context())
	if got := progress(alpha, requestID); got.Delivered != 1 || got.Pending != 0 || got.Inactive != 0 {
		t.Fatal("tenant worker did not publish the opted-in control report", got)
	}
	if got := progress(beta, requestID); got.Delivered != 0 || got.Pending != 0 {
		t.Fatal("unconsented tenant inherited another worker's progress", got)
	}
	readArtifact := func(lane int) []byte {
		t.Helper()
		var owned struct{ Items []store.ReportArtifact }
		sepJSON(t, call(users[lane].cookie, http.MethodGet, "/v1/dashboard-report-artifacts", nil, http.StatusOK), &owned)
		if len(owned.Items) != 1 || owned.Items[0].ID == "" || owned.Items[0].ScheduleID == nil ||
			*owned.Items[0].ScheduleID != schedules[lane].ID || owned.Items[0].Format != schedules[lane].Format {
			t.Fatal("tenant inbox lost explicit ownership or the scheduled format")
		}
		artifact := "/v1/dashboard-report-artifacts/" + owned.Items[0].ID
		call(users[1-lane].cookie, http.MethodGet, artifact, nil, http.StatusNotFound)
		call(provider, http.MethodGet, artifact, nil, http.StatusUnauthorized)
		return call(users[lane].cookie, http.MethodGet, artifact, nil, http.StatusOK)
	}
	if csv := readArtifact(0); len(csv) == 0 || bytes.HasPrefix(csv, []byte("%PDF-")) {
		t.Fatal("tenant worker did not deliver the scheduled CSV")
	}

	consent(1, true)
	second := newRequest()
	if got := queue(beta, second); got.Pending != 1 {
		t.Fatal("explicit sibling consent did not activate its own schedule", got)
	}
	consent(1, false)
	worker.Tick(t.Context())
	if got := progress(beta, second); got.Delivered != 0 || got.Pending != 0 || got.Inactive != 1 {
		t.Fatal("withdrawn consent did not retire pending provider work", got)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(beta)), s.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var next time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT next_run_at FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, beta, schedules[1].ID).Scan(&next); err != nil {
			return err
		}
		if !next.Equal(schedules[1].NextRunAt) {
			t.Fatal("withdrawn provider consent changed the independent tenant schedule")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	consent(1, true)
	third := newRequest()
	if got := queue(beta, third); got.Pending != 1 || got.Queued != 1 {
		t.Fatal("fresh consent did not queue the sibling's own PDF schedule", got)
	}
	worker.Tick(t.Context())
	if got := progress(beta, third); got.Delivered != 1 || got.Pending != 0 {
		t.Fatal("tenant worker did not publish the consented PDF", got)
	}
	if pdf := readArtifact(1); !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf, []byte("/EmbeddedFile")) {
		t.Fatal("tenant worker did not deliver the scheduled PDF evidence attachment")
	}
}

func checkProviderComplianceReportWorkflow(t *testing.T, socket *httptest.Server, cookie *http.Cookie, inventory []Tenant, tenantIDs [2]string) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "provider-compliance-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	first := testsupport.RenderStep{Select: "label:text-is('Report family') + div select", Value: "compliance", Expect: []string{"Compliance evidence", "Tenant consent required"}}
	steps := []testsupport.RenderStep{first}
	page, position, found := 0, 0, 0
	for _, tenant := range inventory {
		if tenant.Status != "active" {
			continue
		}
		if tenant.ID == tenantIDs[0] || tenant.ID == tenantIDs[1] {
			for page < position/100 {
				steps = append(steps, testsupport.RenderStep{Click: "Next report tenants"})
				page++
			}
			steps = append(steps, testsupport.RenderStep{Click: "Select " + tenant.Name, Role: "checkbox"})
			found++
		}
		position++
	}
	if found != 2 {
		t.Fatal("owned tenants are absent from provider inventory")
	}
	steps = append(steps, testsupport.RenderStep{Click: "Queue compliance reports", Expect: []string{
		"2 operational responses", "1 eligible; 1 queued; 1 pending; 0 delivered; 0 inactive", "0 eligible; 0 queued; 0 pending; 0 delivered; 0 inactive",
	}})
	for _, theme := range []string{"light", "dark"} {
		actions := []testsupport.RenderStep{first}
		if theme == "light" {
			actions = steps
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/provider", Cookies: []testsupport.RenderCookie{{Name: cookie.Name, Value: cookie.Value}},
			CAFile: ca, TrustCertFiles: []string{ca}, Theme: theme, Accessibility: true, TimeoutMs: 90000,
			Expect: []string{"Monthly client reports", "Tenant consent required"}, Steps: actions,
			Absent: []string{"Tenant owned CMMC evidence"},
		})
	}
}
