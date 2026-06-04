package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const otherTenant = "00000000-0000-0000-0000-000000000002"

// promServer is a dev-auth server with a seeded in-memory TSDB: two tenants'
// series, so every test can assert the tenant boundary.
func promServer(t *testing.T) (*Server, *tsdb.Memory) {
	t.Helper()
	mem := tsdb.NewMemory()
	now := time.Now().UnixMilli()
	def := tenancy.DefaultTenantID.String()
	err := mem.Write(context.Background(), []tsdb.Series{
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": def, "agent_id": "a1", "target": "db.acme.example"}, Value: 12, TimeMillis: now - 60_000},
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": def, "agent_id": "a1", "target": "db.acme.example"}, Value: 15, TimeMillis: now - 5_000},
		{Metric: "probectl_device_cpu", Labels: map[string]string{"tenant_id": def, "device": "sw1"}, Value: 40, TimeMillis: now - 5_000},
		{Metric: "probectl_result_rtt_ms", Labels: map[string]string{"tenant_id": otherTenant, "agent_id": "evil", "target": "secret.example"}, Value: 99, TimeMillis: now - 5_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	return testServer(fakePinger{}).WithTSDB(mem), mem
}

func doForm(srv *Server, method, path string, form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

type promEnvelope struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
	Error  string          `json:"error"`
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) promEnvelope {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var env promEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return env
}

// TestGrafanaDatasourceSequence drives the exact request sequence Grafana's
// native Prometheus datasource issues — buildinfo, health probe, labels,
// label values, series, range query (form POST), instant query — and asserts
// probectl data renders, tenant-scoped (the S40 "renders in Grafana" test).
func TestGrafanaDatasourceSequence(t *testing.T) {
	srv, _ := promServer(t)

	// 1. buildinfo (capability probe on datasource save)
	env := decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/status/buildinfo"), 200)
	if env.Status != "success" || !strings.Contains(string(env.Data), "version") {
		t.Fatalf("buildinfo = %+v", env)
	}

	// 2. "Save & test" health probe: 1+1 -> scalar 2
	env = decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query", url.Values{"query": {"1+1"}}), 200)
	if !strings.Contains(string(env.Data), `"scalar"`) || !strings.Contains(string(env.Data), `"2"`) {
		t.Fatalf("health probe = %s", env.Data)
	}

	// 3. label discovery (metric browser)
	env = decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/labels"), 200)
	for _, want := range []string{"__name__", "agent_id", "target"} {
		if !strings.Contains(string(env.Data), want) {
			t.Fatalf("labels missing %s: %s", want, env.Data)
		}
	}

	// 4. metric-name values — only the caller's tenant's metrics, never "evil"'s
	env = decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/label/__name__/values"), 200)
	if !strings.Contains(string(env.Data), "probectl_result_rtt_ms") || !strings.Contains(string(env.Data), "probectl_device_cpu") {
		t.Fatalf("metric names = %s", env.Data)
	}

	// 5. series metadata
	env = decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/series?match[]=probectl_result_rtt_ms"), 200)
	if strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("CROSS-TENANT LEAK in series: %s", env.Data)
	}

	// 6. range query, form-POSTed the way Grafana does
	env = decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query_range", url.Values{
		"query": {`probectl_result_rtt_ms{agent_id="a1"}`},
		"start": {"0"}, "end": {"9999999999"}, "step": {"15"},
	}), 200)
	if !strings.Contains(string(env.Data), `"matrix"`) || !strings.Contains(string(env.Data), `"15"`) {
		t.Fatalf("range = %s", env.Data)
	}

	// 7. instant query
	env = decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query", url.Values{"query": {"probectl_result_rtt_ms"}}), 200)
	if !strings.Contains(string(env.Data), `"vector"`) || !strings.Contains(string(env.Data), "db.acme.example") {
		t.Fatalf("instant = %s", env.Data)
	}
	if strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("CROSS-TENANT LEAK in instant query: %s", env.Data)
	}
}

// TestGrafanaTenantBoundary: explicitly asking for another tenant's series
// still returns only the caller's own tenant (the matcher is overwritten).
func TestGrafanaTenantBoundary(t *testing.T) {
	srv, _ := promServer(t)
	rec := doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query", url.Values{
		"query": {`probectl_result_rtt_ms{tenant_id="` + otherTenant + `"}`},
	})
	env := decodeEnvelope(t, rec, 200)
	if strings.Contains(string(env.Data), "secret.example") || strings.Contains(string(env.Data), "evil") {
		t.Fatalf("CROSS-TENANT LEAK: tenant matcher was honored: %s", env.Data)
	}
	// And full PromQL is rejected, not partially evaluated.
	rec = doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query", url.Values{"query": {"rate(probectl_result_rtt_ms[5m])"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PromQL function accepted: %d %s", rec.Code, rec.Body.String())
	}
}

// TestGrafanaRBAC: the datasource routes declare metrics.read / metrics.write
// (RBAC honored — don't leak via Grafana), and unauthenticated calls are 401.
func TestGrafanaRBAC(t *testing.T) {
	srv, _ := promServer(t)
	wantPerm := map[string]string{
		"/v1/grafana/api/v1/query":       ai.PermMetricsRead,
		"/v1/grafana/api/v1/query_range": ai.PermMetricsRead,
		"/v1/grafana/api/v1/series":      ai.PermMetricsRead,
		"/v1/grafana/api/v1/labels":      ai.PermMetricsRead,
		"/v1/prometheus/federate":        ai.PermMetricsRead,
		"/v1/prometheus/write":           permMetricsWrite,
	}
	seen := map[string]bool{}
	for _, rt := range srv.apiRoutes() {
		if want, ok := wantPerm[rt.Pattern]; ok {
			seen[rt.Pattern] = true
			if rt.Permission != want {
				t.Errorf("%s %s permission = %q, want %q", rt.Method, rt.Pattern, rt.Permission, want)
			}
		}
	}
	for p := range wantPerm {
		if !seen[p] {
			t.Errorf("route %s not registered", p)
		}
	}

	// Unauthenticated (session mode, no session): 401, no data.
	cfg := *srv.cfg
	cfg.AuthMode = "session"
	noAuth := New(&cfg, srv.log, fakePinger{}, nil, nil, nil).WithTSDB(tsdb.NewMemory())
	rec := do(noAuth, http.MethodGet, "/v1/grafana/api/v1/labels")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

// TestFederationScrape: the federation endpoint serves the text exposition
// format, tenant-scoped (the S40 federation scrape test).
func TestFederationScrape(t *testing.T) {
	srv, _ := promServer(t)
	rec := do(srv, http.MethodGet, "/v1/prometheus/federate?match[]="+url.QueryEscape("probectl_result_rtt_ms"))
	if rec.Code != 200 {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `probectl_result_rtt_ms{agent_id="a1"`) || !strings.Contains(body, "} 15 ") {
		t.Fatalf("exposition = %q", body)
	}
	if strings.Contains(body, "secret.example") {
		t.Fatalf("CROSS-TENANT LEAK in federation: %q", body)
	}

	// The latest sample only (a scrape, not a dump): value 12 must be absent.
	if strings.Contains(body, "} 12 ") {
		t.Fatalf("federation returned stale samples: %q", body)
	}
}

// TestRemoteWriteIngest: an external Prometheus remote-writes in; the samples
// land tenant-forced and are immediately queryable through the Grafana API.
func TestRemoteWriteIngest(t *testing.T) {
	srv, mem := promServer(t)
	before := mem.Len()

	wr := &prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
		Labels: []*prompb.Label{
			{Name: "__name__", Value: "node_load1"},
			{Name: "instance", Value: "host1:9100"},
			{Name: "tenant_id", Value: otherTenant}, // hostile: must be overwritten
		},
		Samples: []*prompb.Sample{{Value: 0.7, Timestamp: time.Now().UnixMilli()}},
	}}}
	raw, _ := proto.Marshal(wr)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/prometheus/write", strings.NewReader(string(snappy.Encode(nil, raw))))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("write status = %d body=%s", rec.Code, rec.Body.String())
	}
	if mem.Len() != before+1 {
		t.Fatalf("store len = %d, want %d", mem.Len(), before+1)
	}

	// The ingested sample belongs to the CALLER's tenant now.
	got := mem.Query("node_load1", map[string]string{"tenant_id": tenancy.DefaultTenantID.String()})
	if len(got) != 1 || got[0].Labels["instance"] != "host1:9100" {
		t.Fatalf("ingested = %+v", got)
	}
	if leak := mem.Query("node_load1", map[string]string{"tenant_id": otherTenant}); len(leak) != 0 {
		t.Fatalf("CROSS-TENANT WRITE: %+v", leak)
	}

	// Garbage fails closed.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/prometheus/write", strings.NewReader("not snappy"))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage = %d", rec.Code)
	}
}
