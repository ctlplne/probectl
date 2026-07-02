// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

// The S-T7 control-plane legs: the tenant self-view tells the truth in both
// wirings, and the per-tenant query-cost guard answers 429 rate_limited with
// Retry-After on the S23 query surfaces.

func TestFairnessSelfViewUnwired(t *testing.T) {
	srv := testServer(nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/fairness", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Enforcing bool `json:"enforcing"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || got.Enforcing {
		t.Fatalf("an ungated deployment must report enforcing=false: %s (%v)", rr.Body.String(), err)
	}
}

func TestFairnessSelfViewAndQueryGuard(t *testing.T) {
	srv := testServer(nil)
	gate := fairness.NewGate(fairness.Policy{
		QueryConcurrency: 1,
		QueriesPerMin:    600,
		ResultsPerSec:    100,
	}, nil)
	srv.WithFairness(gate)

	// The self-view reports the effective policy + accounting.
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/fairness", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var view struct {
		Enforcing bool             `json:"enforcing"`
		Policy    fairness.Policy  `json:"policy"`
		Queries   map[string]int64 `json:"queries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Enforcing || view.Policy.QueryConcurrency != 1 || view.Policy.ResultsPerSec != 100 {
		t.Fatalf("self-view: %s", rr.Body.String())
	}

	// Saturate the dev tenant's single query slot, then ask: 429.
	release, err := gate.BeginQuery(t.Context(), devTenantID(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ai/ask", strings.NewReader(`{"question":"why is checkout slow?"}`))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("a saturated tenant must get 429, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if !strings.Contains(rr.Body.String(), "rate_limited") {
		t.Fatalf("error code: %s", rr.Body.String())
	}

	// Released slot: the same ask now proceeds past the guard (any non-429
	// outcome means fairness admitted it).
	release()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/ai/ask", strings.NewReader(`{"question":"why is checkout slow?"}`))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusTooManyRequests {
		t.Fatalf("a freed slot must admit the next query: %s", rr.Body.String())
	}

	// The rejection is visible in the tenant's own accounting.
	snap := gate.SnapshotTenant(t.Context(), devTenantID(srv))
	if snap.Queries.RejectedConcurrency != 1 {
		t.Fatalf("query accounting: %+v", snap.Queries)
	}
}

// devTenantID resolves the dev-mode principal's tenant (the default tenant).
func devTenantID(s *Server) string {
	// Dev principals come from the hook now (RED-001) — resolvePrincipal only
	// handles real sessions.
	p, _ := devModeHook(s, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/fairness", nil))
	if p == nil {
		return ""
	}
	return p.TenantID
}

// TestPrometheusReadSurfacesGuard429: every Prometheus-compatible read surface
// is bounded by the same per-tenant query-cost guard, including metadata and
// federation discovery paths that can otherwise fan out to the shared TSDB.
func TestPrometheusReadSurfacesGuard429(t *testing.T) {
	srv := testServer(nil)
	gate := fairness.NewGate(fairness.Policy{QueryConcurrency: 1}, nil)
	srv.WithFairness(gate)
	release, err := gate.BeginQuery(t.Context(), devTenantID(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	endpoints := []string{
		"/v1/grafana/api/v1/status/buildinfo",
		"/v1/grafana/api/v1/query?query=up",
		"/v1/grafana/api/v1/query_range?query=up&start=1780000000&end=1780000060&step=15",
		"/v1/grafana/api/v1/series?match[]=" + url.QueryEscape("up"),
		"/v1/grafana/api/v1/labels",
		"/v1/grafana/api/v1/label/__name__/values",
		"/v1/grafana/api/v1/metadata",
		"/v1/prometheus/federate?match[]=" + url.QueryEscape("up"),
	}
	for _, endpoint := range endpoints {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("%s must 429 when saturated, got %d: %s", endpoint, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Retry-After") == "" {
			t.Fatalf("%s 429 must carry Retry-After", endpoint)
		}
	}
}
