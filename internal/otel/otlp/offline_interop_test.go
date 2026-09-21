// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

func TestOfflineInteropOTelCollectorMetricsTracesLogs(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"collector-token": "tenant-a"})
	seen := map[string]string{}

	mux := http.NewServeMux()
	mux.Handle("/v1/metrics", MetricsHTTPHandler(auth, SinkFunc(func(_ context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error {
		seen["metrics"] = tenant
		if got := ResourceTenant(req.GetResourceMetrics()[0]); got != "tenant-a" {
			t.Fatalf("metrics tenant = %q, want tenant-a", got)
		}
		return nil
	}), 1<<20))
	mux.Handle("/v1/traces", TracesHTTPHandler(auth, TraceSinkFunc(func(_ context.Context, tenant string, req *coltracepb.ExportTraceServiceRequest) error {
		seen["traces"] = tenant
		if got := resourceTenantOf(req.GetResourceSpans()[0].GetResource()); got != "tenant-a" {
			t.Fatalf("traces tenant = %q, want tenant-a", got)
		}
		return nil
	}), 1<<20))
	mux.Handle("/v1/logs", LogsHTTPHandler(auth, LogSinkFunc(func(_ context.Context, tenant string, req *collogspb.ExportLogsServiceRequest) error {
		seen["logs"] = tenant
		if got := resourceTenantOf(req.GetResourceLogs()[0].GetResource()); got != "tenant-a" {
			t.Fatalf("logs tenant = %q, want tenant-a", got)
		}
		return nil
	}), 1<<20))

	metricReq := metricsRequest(resultResourceMetrics(&resultv1.Result{TenantId: "tenant-a", AgentId: "collector-1", CanaryType: "http"}))
	traceReq := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: []*commonpb.KeyValue{}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "GET /healthz"}}}},
	}}}
	logReq := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "collector replay log"}},
		}}}},
	}}}

	postProto := func(path string, msg proto.Message) {
		t.Helper()
		body, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal %s: %v", path, err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://probectl.local"+path, bytes.NewReader(body))
		if req.TLS == nil {
			t.Fatalf("%s replay must model HTTPS, got nil TLS state", path)
		}
		req.Header.Set("Authorization", "Bearer collector-token")
		req.Header.Set("Content-Type", "application/x-protobuf")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%q", path, rr.Code, rr.Body.String())
		}
	}

	postProto("/v1/metrics", metricReq)
	postProto("/v1/traces", traceReq)
	postProto("/v1/logs", logReq)

	for _, signal := range []string{"metrics", "traces", "logs"} {
		if seen[signal] != "tenant-a" {
			t.Fatalf("%s sink tenant = %q, want tenant-a", signal, seen[signal])
		}
	}
}
