// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// OPS-005: /metrics is served in Prometheus text with probectl self-metrics and
// carries no tenant data. AUTHZ-25: the exposition is a fingerprinting surface
// (build_info + pipeline counters), so on the public listener it is gated by the
// configured scrape token — this test was previously an ANONYMOUS scrape (it
// encoded the leak) and now presents the credential a ServiceMonitor would.
func TestMetricsEndpointServesWithScrapeCredential(t *testing.T) {
	const scrapeToken = "service-monitor-scrape-token"
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour, MetricsScrapeToken: scrapeToken}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+scrapeToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics must be reachable with the scrape credential: got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("not Prometheus exposition: %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"probectl_build_info", "probectl_uptime_seconds", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	// Self-metrics only: never a tenant id or per-tenant series.
	if strings.Contains(body, "tenant_id=") {
		t.Fatalf("/metrics must not expose per-tenant series:\n%s", body)
	}
}

func TestMetricsExposeAuditRetentionHealth(t *testing.T) {
	const scrapeToken = "service-monitor-scrape-token"
	cfg := &config.Config{
		HTTPAddr:           ":0",
		AuthMode:           "session",
		HSTSEnabled:        true,
		HSTSMaxAge:         time.Hour,
		MetricsScrapeToken: scrapeToken,
		AuditRetention:     365 * 24 * time.Hour,
		AuditWORMDir:       "/var/lib/probectl/audit-worm",
		SIEMEnabled:        true,
		SIEMEndpoint:       "https://siem.example/ingest",
	}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+scrapeToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{
		"probectl_audit_retention_window_seconds",
		"probectl_audit_retention_raw_rows_aging_out 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing audit-retention health %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "tenant_id=") {
		t.Fatalf("audit retention metrics must not expose tenant labels:\n%s", body)
	}
}
