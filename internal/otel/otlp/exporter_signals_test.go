// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otlp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// TestHTTPExporterTracesReachCollector is the ARCH-003 acceptance test for
// traces: a configured HTTP exporter must POST ingested spans to the
// downstream collector's /v1/traces path, and the spans must arrive intact.
func TestHTTPExporterTracesReachCollector(t *testing.T) {
	type capture struct {
		path string
		req  *coltracepb.ExportTraceServiceRequest
	}
	ch := make(chan capture, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ch <- capture{path: r.URL.Path, req: &req}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp, err := NewHTTPExporter(ExporterConfig{Endpoint: srv.URL + "/v1/metrics", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	req := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key: "probectl.tenant.id", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "tenant-a"}},
		}}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "GET /x"}}}},
	}}}
	if err := exp.ExportTraces(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.path != "/v1/traces" {
		t.Fatalf("traces POSTed to %q, want /v1/traces", got.path)
	}
	rs := got.req.GetResourceSpans()
	if len(rs) != 1 || len(rs[0].GetScopeSpans()) != 1 || rs[0].GetScopeSpans()[0].GetSpans()[0].GetName() != "GET /x" {
		t.Fatalf("span did not reach the collector intact: %+v", got.req)
	}
}

// TestHTTPExporterLogsReachCollector is the ARCH-003 acceptance test for logs.
func TestHTTPExporterLogsReachCollector(t *testing.T) {
	ch := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rl := req.GetResourceLogs()
		if len(rl) == 1 && len(rl[0].GetScopeLogs()) == 1 && len(rl[0].GetScopeLogs()[0].GetLogRecords()) == 1 {
			ch <- r.URL.Path
		} else {
			ch <- "MALFORMED"
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp, err := NewHTTPExporter(ExporterConfig{Endpoint: srv.URL + "/v1/metrics"})
	if err != nil {
		t.Fatal(err)
	}
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "hello"}},
		}}}},
	}}}
	if err := exp.ExportLogs(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if path := <-ch; path != "/v1/logs" {
		t.Fatalf("logs POSTed to %q, want /v1/logs", path)
	}
}

// TestSignalURLDerivation pins the per-signal path mapping.
func TestSignalURLDerivation(t *testing.T) {
	e := &HTTPExporter{url: "https://collector:4318/v1/metrics"}
	if got := e.signalURL("traces"); got != "https://collector:4318/v1/traces" {
		t.Errorf("traces URL = %q", got)
	}
	if got := e.signalURL("logs"); got != "https://collector:4318/v1/logs" {
		t.Errorf("logs URL = %q", got)
	}
	base := &HTTPExporter{url: "https://collector:4318"}
	if got := base.signalURL("traces"); got != "https://collector:4318/v1/traces" {
		t.Errorf("base traces URL = %q", got)
	}
}
