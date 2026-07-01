// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/migrations"
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
		t.Skipf("no database available: %v", err)
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
