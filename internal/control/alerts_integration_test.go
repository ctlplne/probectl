// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/store"
)

func TestAlertsCRUDAPI(t *testing.T) {
	h, _ := setupAPI(t)
	name := fmt.Sprintf("alert-%d", time.Now().UnixNano())

	// Create a threshold rule with a webhook channel carrying a secret.
	rec := apiReq(t, h, http.MethodPost, "/v1/alerts", "", map[string]any{
		"name": name, "metric": "probectl_probe_loss_ratio", "type": "threshold",
		"comparison": "gt", "threshold": 0.5, "severity": "critical", "for_n": 2,
		"channels": []map[string]any{{"type": "webhook", "url": "https://hooks/x", "secret": "sekret"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/v1/alerts/") {
		t.Errorf("Location = %q", loc)
	}
	// ARCH-002/CORRECT-006: setupAPI wires no query backend, so alerting is
	// inactive. The create must still return the BARE rule (the web client +
	// API contract decode alert.Rule) and signal "won't fire yet" via a HEADER,
	// never by wrapping the body. Lock both: the header is set AND the body
	// decodes as a bare rule below.
	if rec.Header().Get("X-Probectl-Alerting-Active") != "false" {
		t.Errorf("inactive-alerting warning header missing on create: %v", rec.Header())
	}
	var created alert.Rule
	mustJSON(t, rec, &created)
	if created.ID == "" || created.Name != name || created.Type != alert.Threshold || created.ForN != 2 {
		t.Fatalf("created = %+v", created)
	}
	if len(created.Channels) != 1 || created.Channels[0].Secret != "***" {
		t.Errorf("webhook secret must be redacted in the response: %+v", created.Channels)
	}

	// Get → 200, secret still redacted.
	rec = apiReq(t, h, http.MethodGet, "/v1/alerts/"+created.ID, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d", rec.Code)
	}
	var got alert.Rule
	mustJSON(t, rec, &got)
	if got.Channels[0].Secret != "***" {
		t.Error("secret leaked on get")
	}

	// Update to a baseline rule, disabled.
	rec = apiReq(t, h, http.MethodPut, "/v1/alerts/"+created.ID, "", map[string]any{
		"name": name, "metric": "probectl_probe_rtt_avg_ms", "type": "baseline",
		"window": 20, "sensitivity": 3, "severity": "warning", "enabled": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body)
	}
	var updated alert.Rule
	mustJSON(t, rec, &updated)
	if updated.Type != alert.Baseline || updated.Window != 20 || updated.Enabled {
		t.Errorf("updated = %+v", updated)
	}

	// Duplicate name → 409.
	if rec = apiReq(t, h, http.MethodPost, "/v1/alerts", "", map[string]any{
		"name": name, "metric": "m", "type": "threshold", "comparison": "gt"}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", rec.Code)
	}

	// Validation → 422.
	for _, bad := range []map[string]any{
		{"metric": "m", "type": "threshold", "comparison": "gt"},       // no name
		{"name": "b1", "metric": "m", "type": "baseline", "window": 1}, // baseline window < 2
		{"name": "b2", "metric": "m", "type": "threshold", "comparison": "zz"},
	} {
		if rec = apiReq(t, h, http.MethodPost, "/v1/alerts", "", bad); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("invalid %v = %d, want 422", bad, rec.Code)
		}
	}

	// Delete → 204, then Get → 404.
	if rec = apiReq(t, h, http.MethodDelete, "/v1/alerts/"+created.ID, "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete = %d, want 204", rec.Code)
	}
	if rec = apiReq(t, h, http.MethodGet, "/v1/alerts/"+created.ID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

// TestAlertsAPITenantIsolation proves an alert rule created in tenant B is
// invisible to the default tenant (RLS, end to end).
func TestAlertsAPITenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		fmt.Sprintf("alertiso-%d", time.Now().UnixNano()), "Alert Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	name := fmt.Sprintf("iso-%d", time.Now().UnixNano())

	rec := apiReq(t, h, http.MethodPost, "/v1/alerts", tn.ID, map[string]any{
		"name": name, "metric": "m", "type": "threshold", "comparison": "gt", "threshold": 1})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create in tenant B = %d: %s", rec.Code, rec.Body)
	}
	var created alert.Rule
	mustJSON(t, rec, &created)

	// Default tenant cannot fetch tenant B's rule (404, not 403).
	if rec = apiReq(t, h, http.MethodGet, "/v1/alerts/"+created.ID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant get = %d, want 404", rec.Code)
	}
	// Tenant B can.
	if rec = apiReq(t, h, http.MethodGet, "/v1/alerts/"+created.ID, tn.ID, nil); rec.Code != http.StatusOK {
		t.Errorf("tenant B get = %d, want 200", rec.Code)
	}
}
