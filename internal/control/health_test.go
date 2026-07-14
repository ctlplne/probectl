// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func do(srv *Server, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id header")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff header")
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing HSTS header")
	}
}

func TestReadyzReady(t *testing.T) {
	rec := do(testServer(fakePinger{}).WithAlertingActive(true), http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Alerting alertingRuntimeHealth `json:"alerting"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Alerting.EvaluatorRunning || body.Alerting.Status != "ok" {
		t.Fatalf("alerting health = %+v, want running/ok", body.Alerting)
	}
}

func TestReadyzReportsAlertingInactive(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("inactive alert evaluator must degrade visibly without making the API unready: %d", rec.Code)
	}
	var body struct {
		Alerting alertingRuntimeHealth `json:"alerting"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Alerting.EvaluatorRunning || body.Alerting.Status != "degraded" {
		t.Fatalf("alerting health = %+v, want inactive/degraded", body.Alerting)
	}
	if !strings.Contains(body.Alerting.Detail, "not evaluated") || body.Alerting.Setup == "" {
		t.Fatalf("inactive alerting health lacks cause/setup: %+v", body.Alerting)
	}
}

func TestReadyzReportsAuditRetentionHealth(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.AuditRetention = 365 * 24 * time.Hour
	srv.cfg.AuditWORMDir = "/var/lib/probectl/audit-worm"
	srv.cfg.SIEMEnabled = true
	srv.cfg.SIEMEndpoint = "https://siem.example/ingest"

	rec := do(srv, http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		AuditRetention auditRetentionHealth `json:"audit_retention"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.AuditRetention.Status != "armed" || !body.AuditRetention.RawRowsAgingOut {
		t.Fatalf("audit retention health = %+v, want armed aging-out posture", body.AuditRetention)
	}
	if !body.AuditRetention.TenantSIEMWatermarkConfigured || !body.AuditRetention.ProviderWORMWatermarkConfigured {
		t.Fatalf("audit retention watermarks not visible: %+v", body.AuditRetention)
	}
}

func TestReadyzReportsBlockedAuditRetention(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.AuditRetention = 365 * 24 * time.Hour

	rec := do(srv, http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		AuditRetention auditRetentionHealth `json:"audit_retention"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.AuditRetention.Status != "blocked" || body.AuditRetention.RawRowsAgingOut {
		t.Fatalf("audit retention health = %+v, want blocked/non-aging posture", body.AuditRetention)
	}
	if len(body.AuditRetention.Notes) == 0 {
		t.Fatal("blocked audit retention must explain which watermark is missing")
	}
}

func TestReadyzDatabaseDown(t *testing.T) {
	rec := do(testServer(fakePinger{err: errors.New("connection refused")}), http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body errorBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "unavailable" {
		t.Errorf("code = %q, want unavailable", body.Error.Code)
	}
	if body.Error.RequestID == "" {
		t.Error("error envelope should include request_id")
	}
}

func TestVersionEndpoint(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var info map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := info["go_version"]; !ok {
		t.Error("version payload missing go_version")
	}
}

func TestOpenAPIEndpoint(t *testing.T) {
	rec := do(testServer(fakePinger{}), http.MethodGet, "/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", doc["openapi"])
	}
}
