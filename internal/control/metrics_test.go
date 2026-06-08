package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

// OPS-005: /metrics is served, pre-auth (like /healthz), in Prometheus text
// with probectl self-metrics — and carries no tenant data.
func TestMetricsEndpointPreAuthAndPrometheus(t *testing.T) {
	cfg := &config.Config{HTTPAddr: ":0", AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour}
	s := New(cfg, logging.New(io.Discard, "error", "json"), nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics must be reachable pre-auth (like /healthz): got %d", rec.Code)
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
