// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/otel"
)

func BenchmarkOTLPHTTPMetricsIngest(b *testing.B) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	body := mustMarshalBench(b, MetricsRequest(ResultResourceMetrics(&resultv1.Result{
		TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "icmp", Success: true,
		DurationNano: 12_000_000, Metrics: map[string]float64{"rtt.avg.ms": 12},
	})))
	h := MetricsHTTPHandler(auth, SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error {
		return nil
	}), int64(len(body))*2)
	benchOTLPHTTP(b, h, "/v1/metrics", body)
}

func BenchmarkOTLPHTTPTracesIngest(b *testing.B) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	body := mustMarshalBench(b, &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: benchResource("tenant-a"),
		}},
	})
	h := TracesHTTPHandler(auth, TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error {
		return nil
	}), int64(len(body))*2)
	benchOTLPHTTP(b, h, "/v1/traces", body)
}

func BenchmarkOTLPHTTPLogsIngest(b *testing.B) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	body := mustMarshalBench(b, &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: benchResource("tenant-a"),
		}},
	})
	h := LogsHTTPHandler(auth, LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error {
		return nil
	}), int64(len(body))*2)
	benchOTLPHTTP(b, h, "/v1/logs", body)
}

func benchOTLPHTTP(b *testing.B, h http.Handler, path string, body []byte) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/x-protobuf")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("%s status = %d, want 200", path, rec.Code)
		}
	}
}

func benchResource(tenant string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
	}}}
}

func mustMarshalBench(b *testing.B, msg proto.Message) []byte {
	b.Helper()
	body, err := proto.Marshal(msg)
	if err != nil {
		b.Fatal(err)
	}
	return body
}
