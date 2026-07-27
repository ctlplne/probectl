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

func TestDashboardManifestRoundTripAndTenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("manifest-a-%d", now.UnixNano()), "Manifest Tenant A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("manifest-b-%d", now.UnixNano()), "Manifest Tenant B")
	if err != nil {
		t.Fatal(err)
	}

	create := apiReq(t, h, http.MethodPost, "/v1/dashboards", tenantA.ID, map[string]any{
		"name": "Tenant " + tenantA.ID + " owner dev", "preset": "operator", "shared": true,
		"definition": map[string]any{
			"absolute_from": now.Add(-time.Hour), "absolute_to": now,
			"provenance":           []string{"collector " + tenantA.ID, "owner dev"},
			"redaction_state":      "token=raw-manifest-secret",
			"coverage_limitations": []string{"host 198.51.100.42 offline"},
			"metrics": map[string]string{
				"z token": "api_key=raw-api-key",
				"a owner": "dev",
			},
		},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create source dashboard = %d: %s", create.Code, create.Body)
	}
	var source store.DashboardView
	if err := json.Unmarshal(create.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}

	first := apiReq(t, h, http.MethodGet, "/v1/dashboards/"+source.ID+"/manifest", tenantA.ID, nil)
	second := apiReq(t, h, http.MethodGet, "/v1/dashboards/"+source.ID+"/manifest", tenantA.ID, nil)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("export manifest = %d/%d: %s / %s", first.Code, second.Code, first.Body, second.Body)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("manifest export is not byte deterministic:\n%s\n%s", first.Body, second.Body)
	}
	if got := first.Header().Get("Content-Disposition"); got != `attachment; filename="probectl-dashboard.json"` {
		t.Fatalf("content disposition = %q", got)
	}
	for _, forbidden := range []string{
		tenantA.ID, source.ID, `"owner_id"`, `"tenant_id"`, `"dev"`, "raw-manifest-secret",
		"raw-api-key", "198.51.100.42",
	} {
		if strings.Contains(first.Body.String(), forbidden) {
			t.Errorf("manifest leaked %q: %s", forbidden, first.Body)
		}
	}
	var manifest dashboardManifest
	if err := json.Unmarshal(first.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.APIVersion != dashboardManifestVersion || manifest.Kind != dashboardManifestKind {
		t.Fatalf("manifest identity = %s/%s", manifest.APIVersion, manifest.Kind)
	}
	if len(manifest.Spec.Definition.Metrics) != 2 ||
		manifest.Spec.Definition.Metrics[0].Name != "a owner" {
		t.Fatalf("manifest metrics not deterministically sorted: %+v", manifest.Spec.Definition.Metrics)
	}

	foreign := apiReq(t, h, http.MethodGet, "/v1/dashboards/"+source.ID+"/manifest", tenantB.ID, nil)
	missing := apiReq(t, h, http.MethodGet, "/v1/dashboards/missing/manifest", tenantB.ID, nil)
	if foreign.Code != http.StatusNotFound || missing.Code != http.StatusNotFound ||
		dashboardErrorShape(t, foreign) != dashboardErrorShape(t, missing) {
		t.Fatalf("foreign and missing manifest exports differ: foreign=%d %s missing=%d %s",
			foreign.Code, foreign.Body, missing.Code, missing.Body)
	}

	preview := apiReq(t, h, http.MethodPost, "/v1/dashboard-manifests/import", tenantA.ID,
		map[string]any{"manifest": manifest, "confirm": false})
	if preview.Code != http.StatusOK {
		t.Fatalf("preview manifest = %d: %s", preview.Code, preview.Body)
	}
	var previewed dashboardManifestImportResponse
	if err := json.Unmarshal(preview.Body.Bytes(), &previewed); err != nil {
		t.Fatal(err)
	}
	if previewed.Status != "preview" || previewed.Dashboard != nil || previewed.Preview.MetricCount != 2 {
		t.Fatalf("unexpected preview: %+v", previewed)
	}
	listAfterPreview := apiReq(t, h, http.MethodGet, "/v1/dashboards", tenantA.ID, nil)
	var listed struct {
		Items []store.DashboardView `json:"items"`
	}
	if err := json.Unmarshal(listAfterPreview.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("preview created storage rows: %+v", listed.Items)
	}

	confirmed := apiReq(t, h, http.MethodPost, "/v1/dashboard-manifests/import", tenantA.ID,
		map[string]any{"manifest": previewed.Manifest, "confirm": true})
	if confirmed.Code != http.StatusCreated {
		t.Fatalf("confirm manifest = %d: %s", confirmed.Code, confirmed.Body)
	}
	var imported dashboardManifestImportResponse
	if err := json.Unmarshal(confirmed.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Status != "created" || imported.Dashboard == nil ||
		imported.Dashboard.ID == source.ID || imported.Dashboard.TenantID != tenantA.ID ||
		imported.Dashboard.OwnerID != "dev" {
		t.Fatalf("server did not derive fresh tenant-owned dashboard identity: %+v", imported)
	}
	foreignImported := apiReq(t, h, http.MethodGet, "/v1/dashboards/"+imported.Dashboard.ID, tenantB.ID, nil)
	if foreignImported.Code != http.StatusNotFound {
		t.Fatalf("tenant B read imported tenant A dashboard = %d: %s", foreignImported.Code, foreignImported.Body)
	}

	unknownVersion := manifest
	unknownVersion.APIVersion = "probectl.io/dashboard/v99"
	if rec := apiReq(t, h, http.MethodPost, "/v1/dashboard-manifests/import", tenantA.ID,
		map[string]any{"manifest": unknownVersion, "confirm": false}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown version = %d: %s", rec.Code, rec.Body)
	}
	var withForeignField map[string]any
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawManifest, &withForeignField); err != nil {
		t.Fatal(err)
	}
	withForeignField["tenant_id"] = tenantA.ID
	if rec := apiReq(t, h, http.MethodPost, "/v1/dashboard-manifests/import", tenantB.ID,
		map[string]any{"manifest": withForeignField, "confirm": true}); rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign tenant field import = %d: %s", rec.Code, rec.Body)
	}
	if rec := apiReq(t, h, http.MethodPost, "/v1/dashboard-manifests/import", tenantA.ID,
		map[string]any{"manifest": map[string]any{"metadata": map[string]any{"name": strings.Repeat("x", 70<<10)}}, "confirm": false}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize manifest = %d: %s", rec.Code, rec.Body)
	}

	auditPage := apiReq(t, h, http.MethodGet, "/v1/audit?limit=1000", tenantA.ID, nil)
	for _, action := range []string{"dashboard.manifest_export", "dashboard.manifest_import"} {
		if !strings.Contains(auditPage.Body.String(), `"action":"`+action+`"`) {
			t.Errorf("missing tamper-evident %s event: %s", action, auditPage.Body)
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
