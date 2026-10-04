// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
)

// authz25Server builds a non-dev (session-mode) control server whose requests
// resolve to NO principal (nil pool → no authenticator), so the handlers see a
// genuinely anonymous caller. A healthy fakePinger keeps /readyz on the ready
// path. An optional scrape token gates /metrics.
func authz25Server(scrapeToken string) *Server {
	cfg := &config.Config{
		HTTPAddr:           ":0",
		AuthMode:           "session",
		HSTSEnabled:        true,
		HSTSMaxAge:         time.Hour,
		MetricsScrapeToken: scrapeToken,
		// Give the full (authenticated) body something to carry, so omitting it
		// for an anonymous caller is a real reduction, not an empty one.
		AuditRetention: 365 * 24 * time.Hour,
		AuditWORMDir:   "/var/lib/probectl/audit-worm",
		SIEMEnabled:    true,
		SIEMEndpoint:   "https://siem.example/ingest",
	}
	return New(cfg, logging.New(io.Discard, "error", "json"), fakePinger{}, nil, nil, nil)
}

// TestAUTHZ25_ReadyzAnonymousOmitsOperatorPosture (AUTHZ-25/RTO-07): an
// anonymous /readyz probe gets status only — never the audit-retention,
// alerting, or cluster posture that is operator reconnaissance. Mirrors the
// /version hardening (SEC-008).
func TestAUTHZ25_ReadyzAnonymousOmitsOperatorPosture(t *testing.T) {
	rec := httptest.NewRecorder()
	authz25Server("").Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous /readyz must stay 200 so probes keep working: got %d", rec.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(body["status"]); got != `"ready"` {
		t.Fatalf("anonymous /readyz status = %s, want \"ready\"", got)
	}
	for _, leak := range []string{"audit_retention", "alerting", "cluster", "volatile_stores"} {
		if _, ok := body[leak]; ok {
			t.Errorf("anonymous /readyz leaked operator posture key %q: %s", leak, rec.Body.String())
		}
	}
}

// TestAUTHZ25_ReadyzAuthenticatedKeepsOperatorPosture: a real operator still
// gets the full audit-retention + alerting posture — the fix narrows the
// anonymous view, it does not break the authenticated one.
func TestAUTHZ25_ReadyzAuthenticatedKeepsOperatorPosture(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{UserID: "ops"}))
	rec := httptest.NewRecorder()
	authz25Server("").Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{"audit_retention", "alerting"} {
		if _, ok := body[want]; !ok {
			t.Errorf("authenticated /readyz must still carry %q: %s", want, rec.Body.String())
		}
	}
}

// TestAUTHZ25_MetricsAnonymousScrapeRefused (AUTHZ-25/PLAT-17/WEB-15): with no
// scrape credential configured, an anonymous /metrics scrape on the public mux
// is refused (401) and returns NO build provenance.
func TestAUTHZ25_MetricsAnonymousScrapeRefused(t *testing.T) {
	rec := httptest.NewRecorder()
	authz25Server("").Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous /metrics must be refused: got %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "probectl_build_info") {
		t.Fatalf("anonymous /metrics leaked build provenance:\n%s", rec.Body.String())
	}
}

// TestAUTHZ25_MetricsScrapeTokenMismatchRefused: a scrape token is configured
// but the caller presents the wrong bearer — still 401, still no build_info.
func TestAUTHZ25_MetricsScrapeTokenMismatchRefused(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer not-the-scrape-token")
	rec := httptest.NewRecorder()
	authz25Server("the-real-scrape-token").Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a mismatched scrape token must be refused: got %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "probectl_build_info") {
		t.Fatalf("mismatched /metrics scrape leaked build provenance:\n%s", rec.Body.String())
	}
}

// TestAUTHZ25_MetricsScrapeTokenAccepted: the matching bearer serves metrics —
// the legitimate ServiceMonitor path keeps working.
func TestAUTHZ25_MetricsScrapeTokenAccepted(t *testing.T) {
	const token = "the-real-scrape-token"
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	authz25Server(token).Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a valid scrape token must serve metrics: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "probectl_build_info") {
		t.Fatalf("credentialed /metrics must return the exposition:\n%s", rec.Body.String())
	}
}
