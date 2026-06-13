// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

// SCALE-010 round trip: a pushed OTLP metrics request is CONSUMED and
// QUERYABLE from the TSDB, tenant-labeled like every other plane.
func TestOTLPPushIsConsumedAndQueryable(t *testing.T) {
	mem := tsdb.NewMemory()
	c := NewOTLPConsumer(nil, mem, testLogger())

	now := uint64(time.Now().UnixNano())
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				kv("probectl.tenant.id", "t-otlp"), kv("service.name", "billing"),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{
					{Name: "http.server.requests", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
						DataPoints: []*metricspb.NumberDataPoint{{
							TimeUnixNano: now,
							Attributes:   []*commonpb.KeyValue{kv("http.method", "GET")},
							Value:        &metricspb.NumberDataPoint_AsInt{AsInt: 42},
						}},
					}}},
					{Name: "process.memory", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
						DataPoints: []*metricspb.NumberDataPoint{{
							TimeUnixNano: now,
							Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 12.5},
						}},
					}}},
					// An empty histogram has no points: it yields no series and
					// is not counted (ARCH-006 conversion handles populated ones).
					{Name: "latency", Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{}}},
				},
			}},
		}},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handle(context.Background(), bus.Message{Key: bus.TenantKey("t-otlp", "x"), Value: payload}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if c.Consumed() != 2 {
		t.Fatalf("consumed = %d, want 2 (sum + gauge)", c.Consumed())
	}

	// Queryable, tenant-scoped, value intact.
	got := mem.Query("probectl_otlp_http_server_requests", map[string]string{"tenant_id": "t-otlp"})
	if len(got) != 1 || got[0].Value != 42 {
		t.Fatalf("sum not queryable: %+v", got)
	}
	if got[0].Labels["http_method"] != "GET" || got[0].Labels["service_name"] != "billing" {
		t.Fatalf("labels lost: %+v", got[0].Labels)
	}
	if g := mem.Query("probectl_otlp_process_memory", map[string]string{"tenant_id": "t-otlp"}); len(g) != 1 || g[0].Value != 12.5 {
		t.Fatalf("gauge not queryable: %+v", g)
	}
	// ARCH-006: histograms are now CONVERTED, not skipped. The empty histogram
	// above has no data points, so it yields no series and nothing is skipped.
	if c.skipped.Load() != 0 {
		t.Fatalf("empty histogram should yield nothing (not skipped): skipped=%d", c.skipped.Load())
	}

	// Malformed payloads drop without failing the stream.
	if err := c.handle(context.Background(), bus.Message{Value: []byte("garbage")}); err != nil {
		t.Fatalf("malformed payload must not error the stream: %v", err)
	}
}
