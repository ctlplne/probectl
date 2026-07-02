// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
	// Range within the SCALE-011 31-day cap (an unbounded 0..9999999999 window
	// is now rejected; use a realistic last-hour window around the inserted data).
	rangeStart := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	rangeEnd := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	env = decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query_range", url.Values{
		"query": {`probectl_result_rtt_ms{agent_id="a1"}`},
		"start": {rangeStart}, "end": {rangeEnd}, "step": {"15"},
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

func TestGrafanaUpstreamTenantBoundaryForHostilePrometheusQueries(t *testing.T) {
	def := tenancy.DefaultTenantID.String()
	var mu sync.Mutex
	var gotQueries []string
	var gotMatches [][]string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery := r.URL.Query().Get("query")
		rawMatches := r.URL.Query()["match[]"]
		mu.Lock()
		if rawQuery != "" {
			gotQueries = append(gotQueries, rawQuery)
		}
		if len(rawMatches) > 0 {
			gotMatches = append(gotMatches, append([]string(nil), rawMatches...))
		}
		mu.Unlock()

		body := ""
		switch r.URL.Path {
		case "/api/v1/query":
			body = hostileVectorPayload(def, otherTenant)
		case "/api/v1/query_range":
			body = hostileMatrixPayload(def, otherTenant)
		case "/api/v1/series":
			body = hostileSeriesPayload(def, otherTenant)
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	srv := testServer(fakePinger{})
	srv.cfg.TSDBMode = "prometheus"
	srv.cfg.TSDBURL = upstream.URL
	srv.WithTSDB(tsdb.NewPrometheus(srv.cfg.TSDBURL))

	env := decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query", url.Values{
		"query": {`probectl_result_rtt_ms{tenant_id="` + otherTenant + `",target=~".*"}`},
	}), 200)
	if strings.Contains(string(env.Data), otherTenant) || strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("upstream response leaked hostile tenant data: %s", env.Data)
	}
	if !strings.Contains(string(env.Data), "db.acme.example") {
		t.Fatalf("default tenant data was filtered out unexpectedly: %s", env.Data)
	}
	mu.Lock()
	capturedQueries := append([]string(nil), gotQueries...)
	mu.Unlock()
	if len(capturedQueries) == 0 || !strings.Contains(capturedQueries[len(capturedQueries)-1], `tenant_id="`+def+`"`) ||
		strings.Contains(capturedQueries[len(capturedQueries)-1], otherTenant) {
		t.Fatalf("upstream instant query was not tenant-forced: %q", capturedQueries)
	}

	rangeStart := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	rangeEnd := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	env = decodeEnvelope(t, doForm(srv, http.MethodPost, "/v1/grafana/api/v1/query_range", url.Values{
		"query": {`probectl_result_rtt_ms{tenant_id="` + otherTenant + `"}`},
		"start": {rangeStart}, "end": {rangeEnd}, "step": {"15"},
	}), 200)
	if strings.Contains(string(env.Data), otherTenant) || strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("upstream range response leaked hostile tenant data: %s", env.Data)
	}

	env = decodeEnvelope(t, do(srv, http.MethodGet,
		"/v1/grafana/api/v1/series?match[]="+url.QueryEscape(`probectl_result_rtt_ms{tenant_id="`+otherTenant+`"}`)), 200)
	if strings.Contains(string(env.Data), otherTenant) || strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("upstream series response leaked hostile tenant data: %s", env.Data)
	}
	mu.Lock()
	capturedMatches := append([][]string(nil), gotMatches...)
	mu.Unlock()
	if len(capturedMatches) == 0 {
		t.Fatal("upstream series request had no match[] selector")
	}
	lastMatches := capturedMatches[len(capturedMatches)-1]
	if len(lastMatches) == 0 || !strings.Contains(lastMatches[len(lastMatches)-1], `tenant_id="`+def+`"`) ||
		strings.Contains(lastMatches[len(lastMatches)-1], otherTenant) {
		t.Fatalf("upstream series match[] was not tenant-forced: %q", lastMatches)
	}

	env = decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/labels"), 200)
	if strings.Contains(string(env.Data), "secret_label") {
		t.Fatalf("upstream label names leaked hostile-only label: %s", env.Data)
	}

	env = decodeEnvelope(t, do(srv, http.MethodGet, "/v1/grafana/api/v1/label/target/values"), 200)
	if strings.Contains(string(env.Data), "secret.example") || !strings.Contains(string(env.Data), "db.acme.example") {
		t.Fatalf("upstream label values were not tenant-filtered: %s", env.Data)
	}

	rec := do(srv, http.MethodGet, "/v1/prometheus/federate?match[]="+url.QueryEscape("probectl_result_rtt_ms"))
	if rec.Code != 200 {
		t.Fatalf("federate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), otherTenant) || strings.Contains(rec.Body.String(), "secret.example") {
		t.Fatalf("upstream federation leaked hostile tenant data: %s", rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/grafana/api/v1/query", strings.NewReader(url.Values{
		"query": {"probectl_result_rtt_ms"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Probectl-Tenant", otherTenant)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	env = decodeEnvelope(t, rec, 200)
	if strings.Contains(string(env.Data), "db.acme.example") || !strings.Contains(string(env.Data), "secret.example") {
		t.Fatalf("non-default tenant was not isolated to its own upstream rows: %s", env.Data)
	}
}

func hostileVectorPayload(def, other string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` +
		`{"metric":{"__name__":"probectl_result_rtt_ms","tenant_id":"` + def + `","target":"db.acme.example"},"value":[1780000000.000,"15"]},` +
		`{"metric":{"__name__":"probectl_result_rtt_ms","tenant_id":"` + other + `","target":"secret.example","secret_label":"x"},"value":[1780000000.000,"99"]}` +
		`]}}`
}

func hostileMatrixPayload(def, other string) string {
	return `{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"__name__":"probectl_result_rtt_ms","tenant_id":"` + def + `","target":"db.acme.example"},"values":[[1780000000.000,"15"]]},` +
		`{"metric":{"__name__":"probectl_result_rtt_ms","tenant_id":"` + other + `","target":"secret.example","secret_label":"x"},"values":[[1780000000.000,"99"]]}` +
		`]}}`
}

func hostileSeriesPayload(def, other string) string {
	return `{"status":"success","data":[` +
		`{"__name__":"probectl_result_rtt_ms","tenant_id":"` + def + `","target":"db.acme.example"},` +
		`{"__name__":"probectl_result_rtt_ms","tenant_id":"` + other + `","target":"secret.example","secret_label":"x"}` +
		`]}`
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

func TestRemoteWritePrometheusModeOverwritesHostileTenantLabels(t *testing.T) {
	def := tenancy.DefaultTenantID.String()
	var mu sync.Mutex
	var gotLabels map[string]string
	upstream := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v1/write" {
			t.Fatalf("unexpected remote-write path %s", r.URL.Path)
		}
		if got := r.Header.Get("Content-Encoding"); got != "snappy" {
			t.Fatalf("content-encoding = %q, want snappy", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read remote-write body: %v", err)
		}
		raw, err := snappy.Decode(nil, body)
		if err != nil {
			t.Fatalf("decode remote-write body: %v", err)
		}
		var wr prompb.WriteRequest
		if err := proto.Unmarshal(raw, &wr); err != nil {
			t.Fatalf("unmarshal remote-write: %v", err)
		}
		if len(wr.Timeseries) != 1 {
			t.Fatalf("remote-write series = %d, want 1", len(wr.Timeseries))
		}
		mu.Lock()
		gotLabels = labelsByName(wr.Timeseries[0].Labels)
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	})

	srv := testServer(fakePinger{})
	srv.cfg.TSDBMode = "prometheus"
	srv.cfg.TSDBURL = "https://prometheus.example"
	srv.WithTSDB(tsdb.NewPrometheusWithClient(srv.cfg.TSDBURL, &http.Client{Transport: upstream}))

	hostile := &prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
		Labels: []*prompb.Label{
			{Name: "__name__", Value: "node_load1"},
			{Name: "instance", Value: "host1:9100"},
			{Name: "tenant_id", Value: otherTenant},
		},
		Samples: []*prompb.Sample{{Value: 0.7, Timestamp: time.Now().UnixMilli()}},
	}}}
	raw, err := proto.Marshal(hostile)
	if err != nil {
		t.Fatalf("marshal hostile write: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/prometheus/write", bytes.NewReader(snappy.Encode(nil, raw)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("write status = %d body=%s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	labels := make(map[string]string, len(gotLabels))
	for k, v := range gotLabels {
		labels[k] = v
	}
	mu.Unlock()
	if labels["tenant_id"] != def {
		t.Fatalf("remote-write tenant_id = %q, want caller tenant %q; labels=%v", labels["tenant_id"], def, labels)
	}
	if strings.Contains(labels["tenant_id"], otherTenant) || labels["instance"] != "host1:9100" || labels["__name__"] != "node_load1" {
		t.Fatalf("unexpected remote-write labels: %v", labels)
	}
}

func labelsByName(labels []*prompb.Label) map[string]string {
	out := make(map[string]string, len(labels))
	for _, label := range labels {
		out[label.GetName()] = label.GetValue()
	}
	return out
}
