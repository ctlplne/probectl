// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func setupMaintenanceAPI(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev"}
	return New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil), db
}

func TestMaintenanceWindowAuditAndTenantIsolation(t *testing.T) {
	srv, db := setupMaintenanceAPI(t)
	tenantA := freshTenant(t, db, "mw-audit-a")
	tenantB := freshTenant(t, db, "mw-audit-b")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv.WithAlertState(tenantA, alert.NewEngine(nil, nil, log))
	srv.WithAlertState(tenantB, alert.NewEngine(nil, nil, log))
	h := srv.Handler()

	body := map[string]any{
		"id": "mw-a", "name": "database patch",
		"starts_at": "2026-06-04T12:00:00Z", "ends_at": "2026-06-04T13:00:00Z",
		"match": map[string]string{"target": "db"}, "rule_ids": []string{"r1"},
	}
	rec := apiReq(t, h, http.MethodPost, "/v1/alerts/maintenance", tenantA, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert tenant A = %d: %s", rec.Code, rec.Body)
	}

	rec = apiReq(t, h, http.MethodGet, "/v1/alerts/maintenance", tenantB, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list tenant B = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "database patch") {
		t.Fatalf("tenant B saw tenant A maintenance window: %s", rec.Body)
	}
	rec = apiReq(t, h, http.MethodDelete, "/v1/alerts/maintenance/mw-a", tenantB, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant B delete tenant A window = %d: %s", rec.Code, rec.Body)
	}
	rec = apiReq(t, h, http.MethodGet, "/v1/alerts/maintenance", tenantA, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "database patch") {
		t.Fatalf("tenant A lost its own window = %d: %s", rec.Code, rec.Body)
	}
	rec = apiReq(t, h, http.MethodDelete, "/v1/alerts/maintenance/mw-a", tenantA, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant A delete = %d: %s", rec.Code, rec.Body)
	}

	rec = apiReq(t, h, http.MethodGet, "/v1/audit?limit=1000", tenantA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list = %d: %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []struct {
			Action string `json:"action"`
			Target string `json:"target"`
			Actor  string `json:"actor"`
			Hash   string `json:"hash"`
		} `json:"items"`
	}
	mustJSON(t, rec, &page)
	var sawUpsert, sawDelete bool
	for _, ev := range page.Items {
		if ev.Target != "mw-a" {
			continue
		}
		switch ev.Action {
		case "alert.maintenance_upsert":
			sawUpsert = ev.Actor == "dev@probectl.local" && ev.Hash != ""
		case "alert.maintenance_delete":
			sawDelete = ev.Actor == "dev@probectl.local" && ev.Hash != ""
		}
	}
	if !sawUpsert || !sawDelete {
		t.Fatalf("maintenance audit events missing: upsert=%v delete=%v page=%+v", sawUpsert, sawDelete, page.Items)
	}
}

func TestAlertWorkflowTenantIsolationAndConnectorReceipt(t *testing.T) {
	srv, db := setupMaintenanceAPI(t)
	tenantA := freshTenant(t, db, "alert-workflow-a")
	tenantB := freshTenant(t, db, "alert-workflow-b")
	srv.WithAlertState(tenantA, newStubAlertState())
	srv.WithAlertState(tenantB, newStubAlertState())
	h := srv.Handler()

	for _, tc := range []struct {
		tenant string
		reason string
	}{
		{tenant: tenantA, reason: "tenant A investigation"},
		{tenant: tenantB, reason: "tenant B investigation"},
	} {
		rec := apiReq(t, h, http.MethodPost, "/v1/alerts/active/ack", tc.tenant,
			map[string]any{"fingerprint": "fp-1", "reason": tc.reason})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"audit_ref":"audit:`) {
			t.Fatalf("ack tenant %s = %d: %s", tc.tenant, rec.Code, rec.Body)
		}
	}

	createIncidentReceipt := func(tenant, title, connector, externalRef string) string {
		t.Helper()
		var incidentID string
		now := time.Now().UTC().Truncate(time.Second)
		err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), db.Pool(),
			func(ctx context.Context, sc tenancy.Scope) error {
				created, err := (store.Incidents{}).Create(ctx, sc, incident.Incident{
					Severity: incident.SeverityCritical, Title: title, Target: "db",
					StartedAt: now, LastSeenAt: now,
				})
				if err != nil {
					return err
				}
				incidentID = created.ID
				return (store.IncidentIntegrations{}).Upsert(ctx, sc, notify.Link{
					IncidentID: incidentID, Connector: connector, ExternalRef: externalRef, Status: "open",
				})
			})
		if err != nil {
			t.Fatalf("create incident receipt for %s: %v", tenant, err)
		}
		return incidentID
	}

	incidentA := createIncidentReceipt(tenantA, "tenant A database", "servicenow", "A-100")
	incidentB := createIncidentReceipt(tenantB, "tenant B database", "jira", "B-200")

	rec := apiReq(t, h, http.MethodGet,
		"/v1/alerts/active/fp-1/workflow?incident_id="+incidentA, tenantA, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tenant A investigation") ||
		!strings.Contains(rec.Body.String(), "A-100") {
		t.Fatalf("tenant A workflow = %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "tenant B investigation") || strings.Contains(rec.Body.String(), "B-200") {
		t.Fatalf("tenant A workflow leaked tenant B operation/connector: %s", rec.Body)
	}

	// A tenant-A incident ID is indistinguishable from absence when tenant B
	// tries to join it, even though both tenants have the same alert fingerprint.
	rec = apiReq(t, h, http.MethodGet,
		"/v1/alerts/active/fp-1/workflow?incident_id="+incidentA, tenantB, nil)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "A-100") {
		t.Fatalf("tenant B joined tenant A incident/connector = %d: %s", rec.Code, rec.Body)
	}

	rec = apiReq(t, h, http.MethodGet,
		"/v1/alerts/active/fp-1/workflow?incident_id="+incidentB, tenantB, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tenant B investigation") ||
		!strings.Contains(rec.Body.String(), "B-200") || strings.Contains(rec.Body.String(), "A-100") {
		t.Fatalf("tenant B workflow = %d: %s", rec.Code, rec.Body)
	}
}
