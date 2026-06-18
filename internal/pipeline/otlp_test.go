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

func TestOTLPMetricBusTenantIsAuthoritative(t *testing.T) {
	mem := tsdb.NewMemory()
	c := NewOTLPConsumer(nil, mem, testLogger())

	payload, err := proto.Marshal(&colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				kv("probectl.tenant.id", "tenant-b"),
				kv("service.name", "billing"),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: "forged.value",
				Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: uint64(time.Now().UnixNano()),
					Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 9},
				}}}},
			}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handle(context.Background(), bus.Message{Key: bus.TenantKey("tenant-a", "replay"), Value: payload}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if c.RejectedTenant() != 1 {
		t.Fatalf("rejected tenant count = %d, want 1", c.RejectedTenant())
	}
	if got := mem.Query("probectl_otlp_forged_value", map[string]string{"tenant_id": "tenant-b"}); len(got) != 0 {
		t.Fatalf("forged metric landed in victim tenant: %+v", got)
	}
	if got := mem.Query("probectl_otlp_forged_value", map[string]string{"tenant_id": "tenant-a"}); len(got) != 0 {
		t.Fatalf("mismatched metric should be dropped, not restamped: %+v", got)
	}
}

func TestOTLPMetricDLQReplayKeepsBusTenantAuthoritative(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	mem := tsdb.NewMemory()
	c := NewOTLPConsumer(b, mem, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	if !b.WaitForSubscribers(ctx, bus.OTLPMetricsTopic, 1) {
		t.Fatal("otlp metrics consumer did not subscribe")
	}

	payload, err := proto.Marshal(&colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				kv("probectl.tenant.id", "tenant-b"),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: "replayed.forgery",
				Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: uint64(time.Now().UnixNano()),
					Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 7},
				}}}},
			}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	replayDone := make(chan ReplayResult, 1)
	go func() {
		res, err := NewDeadLetterReplayer(b, testLogger()).Replay(ctx, ReplayConfig{
			DLQTopic:    bus.DeadLetterOTLPMetricsTopic,
			IdleTimeout: 100 * time.Millisecond,
		})
		if err != nil {
			t.Errorf("replay: %v", err)
		}
		replayDone <- res
	}()
	if !b.WaitForSubscribers(ctx, bus.DeadLetterOTLPMetricsTopic, 1) {
		t.Fatal("otlp metrics DLQ replayer did not subscribe")
	}
	if err := b.Publish(ctx, bus.DeadLetterOTLPMetricsTopic, bus.TenantKey("tenant-a", "dlq"), payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && c.RejectedTenant() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if c.RejectedTenant() != 1 {
		t.Fatalf("rejected tenant count after DLQ replay = %d, want 1", c.RejectedTenant())
	}
	if got := mem.Query("probectl_otlp_replayed_forgery", map[string]string{"tenant_id": "tenant-b"}); len(got) != 0 {
		t.Fatalf("replayed forgery landed in victim tenant: %+v", got)
	}

	select {
	case res := <-replayDone:
		if res.Replayed != 1 || res.SourceTopic != bus.OTLPMetricsTopic {
			t.Fatalf("replay result = %+v, want one replay to %s", res, bus.OTLPMetricsTopic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replay did not terminate on idle")
	}
}
