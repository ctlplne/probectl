// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store"
)

func TestDashboardExportAuditAndTenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("report-a-%d", now.UnixNano()), "Report Tenant A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("report-b-%d", now.UnixNano()), "Report Tenant B")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id   string
		name string
	}{{tenantA.ID, "Report Tenant A"}, {tenantB.ID, "Report Tenant B"}} {
		me := apiReq(t, h, http.MethodGet, "/v1/me", tc.id, nil)
		if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"tenant_name":"`+tc.name+`"`) {
			t.Fatalf("tenant-scoped /me name for %s = %d: %s", tc.id, me.Code, me.Body)
		}
	}
	create := apiReq(t, h, http.MethodPost, "/v1/dashboards", tenantA.ID, map[string]any{
		"name": "Cross-plane posture", "preset": "operator", "shared": true,
		"definition": map[string]any{
			"absolute_from": now.Add(-time.Hour), "absolute_to": now,
			"provenance":           []string{"tenant-scoped control-plane APIs"},
			"redaction_state":      "secrets and direct identifiers removed",
			"coverage_limitations": []string{"offline collectors are not observed"},
			"metrics":              map[string]string{"Active tests": "7", "Open incidents": "1"},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create dashboard = %d: %s", create.Code, create.Body)
	}
	var view store.DashboardView
	if err := json.Unmarshal(create.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}

	foreign := apiReq(t, h, http.MethodGet, "/v1/dashboards/"+view.ID, tenantB.ID, nil)
	missing := apiReq(t, h, http.MethodGet, "/v1/dashboards/missing", tenantB.ID, nil)
	if foreign.Code != http.StatusNotFound || missing.Code != http.StatusNotFound || dashboardErrorShape(t, foreign) != dashboardErrorShape(t, missing) {
		t.Fatalf("foreign and missing dashboard IDs differ: foreign=%d %s missing=%d %s",
			foreign.Code, foreign.Body, missing.Code, missing.Body)
	}

	schedule := apiReq(t, h, http.MethodPost, "/v1/dashboard-report-schedules", tenantA.ID, map[string]any{
		"dashboard_id": view.ID, "name": "Daily posture", "format": "pdf", "cadence": "daily",
		"destination_id": reportInboxDestination, "first_run_at": now.Add(time.Hour),
	})
	if schedule.Code != http.StatusCreated {
		t.Fatalf("create schedule = %d: %s", schedule.Code, schedule.Body)
	}
	supervisor, ok := BuildDashboardReportSupervisor(db.Pool(), time.Minute, nil)
	if !ok {
		t.Fatal("dashboard report supervisor unavailable")
	}
	supervisor.now = func() time.Time { return now.Add(2 * time.Hour) }
	supervisor.Tick(ctx)
	inbox := apiReq(t, h, http.MethodGet, "/v1/dashboard-report-artifacts", tenantA.ID, nil)
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), `"schedule_id"`) || !strings.Contains(inbox.Body.String(), `"format":"pdf"`) {
		t.Fatalf("scheduled report was not delivered to tenant inbox: %d %s", inbox.Code, inbox.Body)
	}
	unsafeSchedule := apiReq(t, h, http.MethodPost, "/v1/dashboard-report-schedules", tenantA.ID, map[string]any{
		"dashboard_id": view.ID, "name": "Unsafe", "format": "csv", "cadence": "daily",
		"destination_id": "unconfigured-webhook", "first_run_at": now.Add(time.Hour),
	})
	if unsafeSchedule.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unconfigured outbound schedule = %d: %s", unsafeSchedule.Code, unsafeSchedule.Body)
	}

	generated := apiReq(t, h, http.MethodPost, "/v1/dashboard-reports", tenantA.ID,
		map[string]any{"dashboard_id": view.ID, "format": "csv"})
	if generated.Code != http.StatusCreated {
		t.Fatalf("generate report = %d: %s", generated.Code, generated.Body)
	}
	var artifact reportArtifactView
	if err := json.Unmarshal(generated.Body.Bytes(), &artifact); err != nil {
		t.Fatal(err)
	}
	foreignDownload := apiReq(t, h, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifact.ID, tenantB.ID, nil)
	missingDownload := apiReq(t, h, http.MethodGet, "/v1/dashboard-report-artifacts/missing", tenantB.ID, nil)
	if foreignDownload.Code != http.StatusNotFound || missingDownload.Code != http.StatusNotFound || dashboardErrorShape(t, foreignDownload) != dashboardErrorShape(t, missingDownload) {
		t.Fatalf("foreign and missing artifact IDs differ: foreign=%d %s missing=%d %s",
			foreignDownload.Code, foreignDownload.Body, missingDownload.Code, missingDownload.Body)
	}
	ownerDownload := apiReq(t, h, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifact.ID, tenantA.ID, nil)
	if ownerDownload.Code != http.StatusOK || !strings.Contains(ownerDownload.Body.String(), "Report Tenant A") || !strings.Contains(ownerDownload.Body.String(), tenantA.ID) {
		t.Fatalf("owner CSV lacks mandatory tenant scope: %d %s", ownerDownload.Code, ownerDownload.Body)
	}

	auditPage := apiReq(t, h, http.MethodGet, "/v1/audit?limit=1000", tenantA.ID, nil)
	if auditPage.Code != http.StatusOK {
		t.Fatalf("audit list = %d: %s", auditPage.Code, auditPage.Body)
	}
	want := map[string]bool{
		"dashboard.save": false, "dashboard.report_schedule": false,
		"dashboard.report_export": false, "dashboard.report_download": false,
		"dashboard.report_delivery": false,
	}
	var page struct {
		Items []struct {
			Action string `json:"action"`
			Hash   string `json:"hash"`
		} `json:"items"`
	}
	if err := json.Unmarshal(auditPage.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	for _, event := range page.Items {
		if _, ok := want[event.Action]; ok && event.Hash != "" {
			want[event.Action] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("missing tamper-evident %s audit event", action)
		}
	}
}

func dashboardErrorShape(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Error.Code + ":" + envelope.Error.Message
}
