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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real Postgres/application-role service entrypoints, complete rendered PDF and
// local scheduling. Principals are injected component identities: this is not
// a TLS/SSO, compiled CLI, native MCP or browser receipt.
func TestStaticReportsPublishReadAndScheduleCompleteMultilingualDocuments(t *testing.T) {
	core, db := setupAPIServerWithLatest(t, nil)
	ctx := t.Context()
	at := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	next := rune(0x4e00)
	text := func(count int) string {
		value := make([]rune, count)
		for i := range value {
			value[i] = next
			next++
		}
		return string(value)
	}
	definition := dashboardDefinition{AbsoluteFrom: at.Add(-time.Hour), AbsoluteTo: at, RedactionState: "none", Metrics: map[string]string{}}
	for i := range 100 {
		definition.Metrics[fmt.Sprintf("%02d", i)+text(26)] = text(80)
	}
	for range 20 {
		definition.Provenance = append(definition.Provenance, text(80))
		definition.CoverageLimitations = append(definition.CoverageLimitations, text(80))
	}
	input, err := cleanDashboardCreate(dashboardCreateRequest{Name: "Complete static multilingual document", Preset: "operator", Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > maxDashboardManifestBytes {
		t.Fatal("full static fixture violates public input envelope", len(encoded), err)
	}
	raw, err := json.Marshal(input.Definition)
	if err != nil {
		t.Fatal(err)
	}
	tenants := make([]string, 2)
	names := []string{"Static tenant A", "Static tenant B"}
	owner := uuid(t)
	views := []string{uuid(t), uuid(t)}
	artifacts := make([]string, 2)
	for i := range tenants {
		tenant, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("static-complete-%d-%d", i, time.Now().UnixNano()), names[i])
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: views[i], OwnerID: owner, Name: input.Name, Preset: input.Preset, Definition: raw})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	request := func(tenant, user, method, path string, body []byte) *http.Request {
		principal := &auth.Principal{TenantID: tenant, UserID: user, Permissions: map[string]bool{"metrics.read": true}}
		bound := auth.WithPrincipal(tenancy.WithTenant(ctx, tenancy.ID(tenant)), principal)
		return httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(bound)
	}
	prove := func(index int, id string) {
		t.Helper()
		req := request(tenants[index], owner, http.MethodGet, "/v1/dashboard-report-artifacts/"+id, nil)
		req.SetPathValue("id", id)
		reply := httptest.NewRecorder()
		if err := core.downloadDashboardReportArtifact(reply, req); err != nil {
			t.Fatal("complete static download failed", err)
		}
		if reply.Code != http.StatusOK || reply.Header().Get("Content-Type") != "application/pdf" || len(reply.Header().Get("X-Report-SHA256")) != 64 {
			t.Fatal("static download lost complete media/integrity framing")
		}
		doc := reporting.Document{Title: input.Name, TenantName: names[index], TenantScope: tenants[index], AbsoluteFrom: definition.AbsoluteFrom, AbsoluteTo: definition.AbsoluteTo, Metrics: definition.Metrics, Provenance: definition.Provenance, CoverageLimitations: definition.CoverageLimitations}
		full, err := staticDocumentSemanticText(reply.Body.Bytes(), doc)
		if err != nil || !strings.Contains(full, input.Name) {
			t.Fatal("published static PDF lost complete original fields", err)
		}
		t.Logf("complete static service lane=%d input_bytes=%d body_bytes=%d full_metrics=%d provenance=%d coverage=%d", index, len(encoded), reply.Body.Len(), len(definition.Metrics), len(definition.Provenance), len(definition.CoverageLimitations))
	}
	for i, tenant := range tenants {
		body, err := json.Marshal(reportGenerateRequest{DashboardID: views[i], Format: "pdf"})
		if err != nil {
			t.Fatal(err)
		}
		reply := httptest.NewRecorder()
		req := request(tenant, owner, http.MethodPost, "/v1/dashboard-reports", body)
		if err := core.handleGenerateDashboardReport(reply, req); err != nil || reply.Code != http.StatusCreated {
			t.Fatal("complete static publication refused", err, reply.Code)
		}
		var item reportArtifactView
		if err := json.Unmarshal(reply.Body.Bytes(), &item); err != nil || item.ID == "" {
			t.Fatal("static generation response invalid", err)
		}
		artifacts[i] = item.ID
		prove(i, item.ID)
		listed := httptest.NewRecorder()
		if err := core.listCurrentReportArtifactMetadata(listed, request(tenant, owner, http.MethodGet, "/v1/dashboard-report-artifacts", nil)); err != nil || !strings.Contains(listed.Body.String(), item.ID) {
			t.Fatal("static document metadata missing from current list", err)
		}
	}
	for _, foreign := range []struct{ tenant, user string }{{tenants[1], owner}, {tenants[0], uuid(t)}} {
		req := request(foreign.tenant, foreign.user, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifacts[0], nil)
		req.SetPathValue("id", artifacts[0])
		reply := httptest.NewRecorder()
		if err := core.downloadDashboardReportArtifact(reply, req); err == nil || reply.Body.Len() != 0 {
			t.Fatal("foreign static artifact released bytes", err)
		}
	}
	due := time.Now().UTC().Add(-time.Minute)
	schedule := uuid(t)
	bound := tenancy.WithTenant(ctx, tenancy.ID(tenants[0]))
	if err := tenancy.InTenant(bound, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.DashboardReports{}).CreateSchedule(ctx, sc, store.ReportScheduleInput{ID: schedule, DashboardID: views[0], OwnerID: owner, Name: "Complete static schedule", Format: "pdf", Cadence: "daily", DestinationID: reportInboxDestination, NextRunAt: due})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	supervisor, ok := BuildDashboardReportSupervisor(core.pool, time.Minute, nil)
	if !ok {
		t.Fatal("static scheduler unavailable")
	}
	supervisor.WithReportSources(core)
	for range 2 {
		if err := supervisor.materializeTenantReports(bound, tenants[0], due.Add(time.Second)); err != nil {
			t.Fatal("complete static local schedule refused", err)
		}
	}
	var scheduled string
	if err := tenancy.InTenant(bound, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2`, tenants[0], schedule).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatal("static local schedule did not publish exactly once", count)
		}
		return sc.Q.QueryRow(ctx, `SELECT id FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2`, tenants[0], schedule).Scan(&scheduled)
	}); err != nil {
		t.Fatal(err)
	}
	prove(0, scheduled)
	old := core.cfg.ReportMaxBytes
	core.cfg.ReportMaxBytes = 1024
	defer func() { core.cfg.ReportMaxBytes = old }()
	req := request(tenants[0], owner, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifacts[0], nil)
	req.SetPathValue("id", artifacts[0])
	reply := httptest.NewRecorder()
	if err := core.downloadDashboardReportArtifact(reply, req); err == nil || reply.Body.Len() != 0 {
		t.Fatal("static small-budget read released partial body", err)
	}
}
