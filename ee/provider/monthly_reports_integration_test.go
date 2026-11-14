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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
)

// This proves the commercial build seam over real TLS HTTP, provider MFA and
// tenant-session authority, PG/RLS and the existing worker. Backdated change
// events are modeled; full monthly source totals and real senders are separate.
func TestProviderMonthlyReportsDeliverSeparateTenantOwnedPacks(t *testing.T) {
	s := newSepStack(t, func(core *control.Server) {
		core.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	})
	op := s.seedAdminOperator(t)
	tenants := []string{s.provisionTenant(t, op, "monthly-a"), s.provisionTenant(t, op, "monthly-b")}
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
	t.Log("real-integration: commercial provider build seam, MFA operator and tenant sessions over verified HTTPS, tenant-consented worker, separate PG/RLS six-section packs and original change IDs; historical changes modeled; rendered UI, real senders and full monthly source totals remain separate")
}
