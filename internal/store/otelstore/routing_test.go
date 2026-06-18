// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otelstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// TENANT-001: a siloed tenant's spans/logs (highest PII) must route to its
// per-tenant database (and residency data plane), not the shared pooled tables.
func TestOtelWriteRoutesPerTarget(t *testing.T) {
	type hit struct{ host, query string }
	var mu sync.Mutex
	var hits []hit
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.Query().Get("query"))
		hits = append(hits, hit{r.Host, q})
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`)) // otel reads decode {"data":...}
	}
	shared := httptest.NewServer(http.HandlerFunc(h))
	defer shared.Close()
	plane := httptest.NewServer(http.HandlerFunc(h))
	defer plane.Close()

	c, err := NewClickHouse(shared.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		switch tenant {
		case "siloed":
			return Target{Database: "probectl_t_abc"}, nil
		case "residency":
			return Target{BaseURL: plane.URL, Database: "probectl_t_eu"}, nil
		case "broken":
			return Target{}, errors.New("registry down")
		default:
			return Target{}, nil
		}
	})

	now := time.Now()
	if err := c.WriteSpans(context.Background(), []Span{
		{TenantID: "pooled", TraceID: "a", SpanID: "1", Start: now},
		{TenantID: "siloed", TraceID: "b", SpanID: "2", Start: now},
		{TenantID: "residency", TraceID: "c", SpanID: "3", Start: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteLogs(context.Background(), []LogRecord{
		{TenantID: "siloed", TS: now, Body: "x"},
	}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	inserts := map[string]string{}
	for _, x := range hits {
		if strings.HasPrefix(x.query, "INSERT INTO ") {
			inserts[strings.Fields(strings.TrimPrefix(x.query, "INSERT INTO "))[0]] = x.host
		}
	}
	mu.Unlock()
	sharedHost := strings.TrimPrefix(shared.URL, "http://")
	planeHost := strings.TrimPrefix(plane.URL, "http://")
	if inserts["probectl_otel_spans"] != sharedHost {
		t.Fatalf("pooled spans must land in the shared table: %+v", inserts)
	}
	if inserts["probectl_t_abc.probectl_otel_spans"] != sharedHost {
		t.Fatalf("siloed spans must land in the tenant database: %+v", inserts)
	}
	if inserts["probectl_t_abc.probectl_otel_logs"] != sharedHost {
		t.Fatalf("siloed logs must land in the tenant database: %+v", inserts)
	}
	if inserts["probectl_t_eu.probectl_otel_spans"] != planeHost {
		t.Fatalf("residency spans must land on the pinned data plane: %+v", inserts)
	}

	if err := c.WriteSpans(context.Background(), []Span{{TenantID: "broken", TraceID: "z", SpanID: "9", Start: now}}); err == nil {
		t.Fatal("a routing error must fail the write (fail closed)")
	}
}

// SCALE-001: OTLP trace/log writes must use the same bounded ClickHouse write
// shape as flowstore: chunk large routed groups and use async_insert so high
// signal volume does not create one giant request body or one part per batch.
func TestOtelWritesChunkLargeBatchesAndUseAsyncInsert(t *testing.T) {
	type insertHit struct {
		query string
		rows  int
	}
	var mu sync.Mutex
	var spanHits, logHits []insertHit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		body, _ := io.ReadAll(r.Body)
		rows := strings.Count(string(body), "\n")
		mu.Lock()
		switch {
		case strings.HasPrefix(q, "INSERT INTO "+spansTable+" ") && strings.Contains(q, "FORMAT JSONEachRow"):
			spanHits = append(spanHits, insertHit{query: q, rows: rows})
		case strings.HasPrefix(q, "INSERT INTO "+logsTable+" ") && strings.Contains(q, "FORMAT JSONEachRow"):
			logHits = append(logHits, insertHit{query: q, rows: rows})
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	n := maxInsertChunk + 1
	spans := make([]Span, n)
	logs := make([]LogRecord, n)
	for i := 0; i < n; i++ {
		spans[i] = Span{TenantID: "pooled", TraceID: "trace", SpanID: fmt.Sprintf("%016x", i+1), Start: now}
		logs[i] = LogRecord{TenantID: "pooled", TS: now, Body: "line"}
	}
	if err := c.WriteSpans(context.Background(), spans); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteLogs(context.Background(), logs); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	for name, hits := range map[string][]insertHit{"spans": spanHits, "logs": logHits} {
		if len(hits) != 2 {
			t.Fatalf("%s: %d rows produced %d INSERT POSTs, want 2 chunks at %d", name, n, len(hits), maxInsertChunk)
		}
		totalRows := 0
		for _, h := range hits {
			if h.rows > maxInsertChunk {
				t.Fatalf("%s: chunk has %d rows, want <= %d", name, h.rows, maxInsertChunk)
			}
			totalRows += h.rows
			if !strings.Contains(h.query, "SETTINGS async_insert=1, wait_for_async_insert=1") {
				t.Fatalf("%s: INSERT missing async durability settings: %s", name, h.query)
			}
		}
		if totalRows != n {
			t.Fatalf("%s: encoded %d rows, want %d", name, totalRows, n)
		}
	}
}

func TestOtelWriteMetricsExposeChunksBacklogAndLatency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	reg := metrics.New("test", "abc")
	c.WithMetrics(reg)

	now := time.Now()
	if err := c.WriteSpans(context.Background(), []Span{
		{TenantID: "pooled", TraceID: "trace", SpanID: "1", Start: now},
		{TenantID: "pooled", TraceID: "trace", SpanID: "2", Start: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteLogs(context.Background(), []LogRecord{
		{TenantID: "pooled", TS: now, Body: "line"},
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{
		"probectl_otelstore_spans_insert_rows_total 2",
		"probectl_otelstore_spans_insert_chunks_total 1",
		"probectl_otelstore_spans_insert_inflight 0",
		"probectl_otelstore_spans_insert_last_latency_seconds",
		"probectl_otelstore_logs_insert_rows_total 1",
		"probectl_otelstore_logs_insert_chunks_total 1",
		"probectl_otelstore_logs_insert_inflight 0",
		"probectl_otelstore_logs_insert_last_latency_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, body)
		}
	}
}

// TENANT-001: reads route to the tenant's database too.
func TestOtelQueryRoutesToTenantStore(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.RawQuery)
		queries = append(queries, q)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.WithRouter(func(tenant string) (Target, error) {
		if tenant == "siloed" {
			return Target{Database: "probectl_t_x"}, nil
		}
		return Target{}, nil
	})
	if _, err := c.QuerySpans(context.Background(), "siloed", SpanQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.QueryLogs(context.Background(), "siloed", LogQuery{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	var spansSeen, logsSeen bool
	for _, qs := range queries {
		if strings.Contains(qs, "probectl_t_x.probectl_otel_spans") {
			spansSeen = true
		}
		if strings.Contains(qs, "probectl_t_x.probectl_otel_logs") {
			logsSeen = true
		}
		if strings.Contains(qs, "tenant_id='siloed'") {
			t.Fatalf("raw tenant literal in SQL (must be bound): %s", qs)
		}
	}
	if !spansSeen || !logsSeen {
		t.Fatalf("siloed reads did not route to the tenant database: %v", queries)
	}
}

// TENANT-001: provisioning + teardown DDL shapes for a siloed otel database.
func TestOtelEnsureAndDropTenantDatabase(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q, _ := url.QueryUnescape(r.URL.Query().Get("query"))
		queries = append(queries, q)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[]}`)) // otel reads decode {"data":...}
	}))
	defer srv.Close()
	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}, 30); err != nil {
		t.Fatal(err)
	}
	if err := c.DropTenantDatabase(context.Background(), Target{Database: "probectl_t_y"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS probectl_t_y",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_otel_spans",
		"CREATE TABLE IF NOT EXISTS probectl_t_y.probectl_otel_logs",
		"DROP DATABASE IF EXISTS probectl_t_y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DDL missing %q in:\n%s", want, joined)
		}
	}
}
