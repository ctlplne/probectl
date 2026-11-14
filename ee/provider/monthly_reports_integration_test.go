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
	"encoding/csv"
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

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// This proves the commercial build seam over real TLS HTTP, provider MFA and
// tenant-session authority, PG/RLS and the existing worker. Backdated change
// events are modeled; full monthly source totals and real senders are separate.
func TestProviderMonthlyReportsDeliverSeparateTenantOwnedPacks(t *testing.T) {
	proveProviderMonthlyPacks(t, false)
}

// Runs in the existing post-web-build integration lane, where Chromium and the
// production commercial bundle are available. Missing rendering is a refusal,
// not a substitute for the separate HTTP-only acceptance test.
func TestProviderMonthlyReportsRealTLSAndPairedThemes(t *testing.T) {
	proveProviderMonthlyPacks(t, true)
}

func proveProviderMonthlyPacks(t *testing.T, render bool) {
	t.Helper()
	s := newSepStack(t, func(core *control.Server) {
		core.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	})
	op := s.seedAdminOperator(t)
	names := []string{"monthly-a-" + strings.ReplaceAll(s.suffix, ".", "-"), "monthly-b-" + strings.ReplaceAll(s.suffix, ".", "-")}
	tenants := []string{s.provisionTenant(t, op, names[0]), s.provisionTenant(t, op, names[1])}
	users := []*sepTenantUser{s.tenantAdmin(t, tenants[0], "monthly-a-"+s.suffix+"@example.test"), s.tenantAdmin(t, tenants[1], "monthly-b-"+s.suffix+"@example.test")}
	socket := httptest.NewTLSServer(s.h)
	defer socket.Close()
	call := func(cookie *http.Cookie, method, path string, input any) (int, []byte) {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(raw)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(cookie)
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	providerCookie := &http.Cookie{Name: SessionCookie, Value: op.token}
	from, _, err := reporting.ClientReportMonth("", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	schedules := make([]store.ReportSchedule, 2)
	events := make([][]string, 2)
	for lane, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), s.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			for index := range lane + 2 {
				item, err := (store.ChangeEvents{}).Create(ctx, sc, change.Event{Source: "generic", Kind: change.KindDeploy, Title: "owned-monthly-change", OccurredAt: from.Add(time.Duration(index+1) * time.Hour)})
				if err != nil {
					return err
				}
				events[lane] = append(events[lane], item.ID)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		code, raw := call(users[lane].cookie, http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{Name: "Owned monthly pack", Preset: "operator", Definition: reporting.DashboardDefinition{Provenance: []string{"retained monthly tenant originals"}, RedactionState: "metadata only", CoverageLimitations: []string{"modeled change history; full source totals proved separately"}, ClientReport: &reporting.ClientReportDefinition{CapacityTargets: []reporting.ClientReportCapacityTarget{}}}})
		if code != http.StatusCreated {
			t.Fatal("tenant monthly view failed", code, string(raw))
		}
		var view store.DashboardView
		sepJSON(t, raw, &view)
		code, raw = call(users[lane].cookie, http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Owned provider monthly", Format: "csv", Cadence: "monthly", DestinationID: "tenant-report-inbox", FirstRunAt: time.Now().UTC().Add(24 * time.Hour)})
		if code != http.StatusCreated {
			t.Fatal("tenant monthly schedule failed", code, string(raw))
		}
		sepJSON(t, raw, &schedules[lane])
		code, _ = call(users[lane].cookie, http.MethodPatch, "/v1/dashboard-report-schedules/"+schedules[lane].ID, map[string]bool{"provider_trigger_allowed": true})
		if code != http.StatusOK {
			t.Fatal("current tenant owner could not consent", code)
		}
	}
	requestID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	var ca string
	if render {
		ca = filepath.Join(t.TempDir(), "provider-ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		code, raw := call(providerCookie, http.MethodGet, "/provider/v1/tenants", nil)
		var inventory struct {
			Items []Tenant `json:"items"`
		}
		sepJSON(t, raw, &inventory)
		if code != http.StatusOK {
			t.Fatal("provider inventory unavailable", code)
		}
		positions := map[string]int{}
		active := 0
		for _, item := range inventory.Items {
			if item.Status != "active" {
				continue
			}
			positions[item.ID] = active
			active++
		}
		steps := []testsupport.RenderStep{}
		page := 0
		for lane, tenant := range tenants {
			position, exists := positions[tenant]
			if !exists {
				t.Fatal("new monthly tenant missing from provider inventory")
			}
			for page < position/100 {
				steps = append(steps, testsupport.RenderStep{Click: "Next report tenants"})
				page++
			}
			for page > position/100 {
				steps = append(steps, testsupport.RenderStep{Click: "Previous report tenants"})
				page--
			}
			steps = append(steps, testsupport.RenderStep{Click: "Select " + names[lane], Role: "checkbox"})
		}
		steps = append(steps, testsupport.RenderStep{Click: "Queue monthly reports", Expect: []string{"2 operational responses", "1 eligible; 1 queued; 1 pending; 0 delivered; 0 inactive"}})
		for _, theme := range []string{"light", "dark"} {
			var actions []testsupport.RenderStep
			if theme == "light" {
				actions = steps
			}
			testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/provider", Cookies: []testsupport.RenderCookie{{Name: SessionCookie, Value: op.token}}, CAFile: ca, TrustCertFiles: []string{ca}, Theme: theme, Accessibility: true, TimeoutMs: 90000, Expect: []string{"Monthly client reports", "Tenant consent required"}, Steps: actions, Controls: []testsupport.RenderControl{{Role: "button", Name: "Queue monthly reports"}, {Role: "button", Name: "Select all active tenants"}}})
		}
		var first string
		for lane, tenant := range tenants {
			var id string
			err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), s.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT provider_request_id::text FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, tenant, schedules[lane].ID).Scan(&id)
			})
			if err != nil || id == "" {
				t.Fatal("rendered provider queue did not retain tenant request", err)
			}
			if lane == 0 {
				first = id
			} else if id != first {
				t.Fatal("one provider-console run did not use one request identity")
			}
		}
		requestID = first
	} else {
		for _, tenant := range tenants {
			code, raw := call(providerCookie, http.MethodPost, "/provider/v1/tenants/"+tenant+"/monthly-reports", map[string]string{"request_id": requestID})
			var progress reporting.MonthlyReportQueueResult
			sepJSON(t, raw, &progress)
			var fields map[string]json.RawMessage
			sepJSON(t, raw, &fields)
			if code != http.StatusAccepted || progress.TenantID != tenant || progress.Queued != 1 || progress.Pending != 1 || len(fields) != 7 {
				t.Fatal("provider exposed more than isolated queue counts", code)
			}
		}
	}
	worker, ok := control.BuildDashboardReportSupervisor(s.db.Pool(), time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok {
		t.Fatal("monthly worker unavailable")
	}
	worker.WithReportSources(s.srv).Tick(t.Context())
	artifacts := make([]string, 2)
	for lane, tenant := range tenants {
		code, raw := call(providerCookie, http.MethodGet, "/provider/v1/tenants/"+tenant+"/monthly-reports/"+requestID, nil)
		var progress reporting.MonthlyReportQueueResult
		sepJSON(t, raw, &progress)
		if code != http.StatusOK || progress.Delivered != 1 || progress.Pending != 0 || progress.Inactive != 0 {
			t.Fatal("tenant worker did not finish the provider request", code, progress)
		}
		code, raw = call(users[lane].cookie, http.MethodGet, "/v1/dashboard-report-artifacts", nil)
		var inbox struct {
			Items []store.ReportArtifact `json:"items"`
		}
		sepJSON(t, raw, &inbox)
		if code != http.StatusOK || len(inbox.Items) != 1 || inbox.Items[0].ScheduleID == nil || *inbox.Items[0].ScheduleID != schedules[lane].ID {
			t.Fatal("provider run did not make one separate tenant pack", code)
		}
		artifacts[lane] = inbox.Items[0].ID
		code, raw = call(users[lane].cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifacts[lane], nil)
		if code != http.StatusOK || bytes.Contains(raw, []byte(tenants[1-lane])) {
			t.Fatal("monthly pack crossed tenant data", code)
		}
		reader := csv.NewReader(bytes.NewReader(raw))
		reader.FieldsPerRecord = -1
		rows, err := reader.ReadAll()
		if err != nil {
			t.Fatal("provider pack is not complete CSV", err)
		}
		sections := map[string]bool{}
		for _, row := range rows {
			if len(row) == 2 && row[0] == "table_id" {
				sections[row[1]] = true
			}
		}
		if len(sections) != 6 {
			t.Fatal("provider pack lost a monthly section")
		}
		for _, id := range events[lane] {
			if !bytes.Contains(raw, []byte(id)) {
				t.Fatal("provider pack lost its original change identity")
			}
		}
		for _, id := range events[1-lane] {
			if bytes.Contains(raw, []byte(id)) {
				t.Fatal("provider pack exposed a sibling original")
			}
		}
		if render {
			for _, theme := range []string{"light", "dark"} {
				download := filepath.Join(t.TempDir(), "monthly.csv")
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/dashboards?view=" + inbox.Items[0].DashboardID, Cookies: []testsupport.RenderCookie{{Name: users[lane].cookie.Name, Value: users[lane].cookie.Value}}, CAFile: ca, TrustCertFiles: []string{ca}, Theme: theme, Accessibility: true, TimeoutMs: 90000, Expect: []string{"Saved views and report delivery", "Owned monthly pack", "Completed calendar month", "Current source access is checked for every report."}, Absent: events[1-lane], Steps: []testsupport.RenderStep{{Click: inbox.Items[0].Filename, Role: "link", Download: download}}})
				body, err := os.ReadFile(download)
				if err != nil || !bytes.Equal(body, raw) {
					t.Fatal("served tenant inbox changed the complete monthly download", err)
				}
			}
		}
	}
	for lane := range tenants {
		path := "/v1/dashboard-report-artifacts/" + artifacts[1-lane]
		if code, raw := call(users[lane].cookie, http.MethodGet, path, nil); code != http.StatusNotFound || strings.Contains(string(raw), "table_id") {
			t.Fatal("tenant read a sibling provider-generated pack", code)
		}
		if code, raw := call(providerCookie, http.MethodGet, path, nil); code != http.StatusUnauthorized || strings.Contains(string(raw), "table_id") {
			t.Fatal("operator queue authority became report-read authority", code)
		}
	}
	t.Log("real-integration: commercial provider build seam, MFA operator and tenant sessions over verified HTTPS, tenant-consented worker, separate PG/RLS six-section packs and original change IDs; historical changes modeled; real senders and full monthly source totals remain separate; both-theme served UI executes only in the rendered root")
}
