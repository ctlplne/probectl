package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// OPS-005: the registry exposes valid Prometheus text with build info,
// runtime stats, and registered counters/gauges — and never anything
// tenant-shaped.
func TestRegistryExposesPrometheusText(t *testing.T) {
	r := New("1.2.3", "abc1234")
	hits := r.Counter("probectl_http_requests_total", "Total HTTP requests served.")
	hits.Add(5)
	hits.Inc()
	r.Gauge("probectl_tenants_active", "Active tenants.", func() float64 { return 7 })

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("wrong content-type: %q", ct)
	}
	body := rec.Body.String()

	for _, want := range []string{
		`probectl_build_info{version="1.2.3",commit="abc1234"} 1`,
		"probectl_http_requests_total 6",
		"probectl_tenants_active 7",
		"go_goroutines ",
		"go_memstats_heap_alloc_bytes ",
		"probectl_uptime_seconds ",
		"process_start_time_seconds ",
		"# TYPE probectl_http_requests_total counter",
		"# TYPE probectl_tenants_active gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}

// Counters are concurrency-safe and the same name returns the same counter.
func TestCounterIdempotentAndConcurrent(t *testing.T) {
	r := New("v", "c")
	c1 := r.Counter("probectl_x_total", "x")
	c2 := r.Counter("probectl_x_total", "x") // same name → same counter
	if c1 != c2 {
		t.Fatal("Counter must return the same instance for a repeated name")
	}
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 1000; j++ {
				c1.Inc()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if c2.Value() != 10000 {
		t.Fatalf("counter race lost increments: %d", c2.Value())
	}
}
