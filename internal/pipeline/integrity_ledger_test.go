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
	selfmetrics "github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestPipelineIntegrityLedgerCountsMalformedPayloads(t *testing.T) {
	ctx := context.Background()
	garbage := bus.Message{Key: bus.TenantKey("t-ledger", "a"), Value: []byte("garbage")}

	cases := []struct {
		name       string
		metricName string
		run        func(*selfmetrics.Registry) (IntegrityStats, error)
	}{
		{
			name:       "results",
			metricName: "probectl_pipeline_results_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewConsumer(nil, tsdb.NewMemory(), "test", testLogger()).WithMetrics(reg)
				err := c.handle(ctx, garbage)
				return c.IntegrityStats(), err
			},
		},
		{
			name:       "device",
			metricName: "probectl_pipeline_device_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewDeviceConsumer(nil, tsdb.NewMemory(), testLogger()).WithMetrics(reg)
				err := c.handleLane(ctx, garbage, "")
				return c.IntegrityStats(), err
			},
		},
		{
			name:       "flow",
			metricName: "probectl_pipeline_flow_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewFlowConsumer(nil, flowstore.NewMemory(), nil, testLogger()).WithMetrics(reg)
				err := c.handleLane(ctx, garbage, "")
				return c.IntegrityStats(), err
			},
		},
		{
			name:       "otlp-metrics",
			metricName: "probectl_pipeline_otlp_metrics_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewOTLPConsumer(nil, tsdb.NewMemory(), testLogger()).WithMetrics(reg)
				err := c.handle(ctx, garbage)
				return c.IntegrityStats(), err
			},
		},
		{
			name:       "otlp-traces",
			metricName: "probectl_pipeline_otlp_traces_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewOTLPTraceConsumer(nil, otelstore.NewMemory(), testLogger()).WithMetrics(reg)
				err := c.handle(ctx, garbage)
				return c.IntegrityStats(), err
			},
		},
		{
			name:       "otlp-logs",
			metricName: "probectl_pipeline_otlp_logs_malformed_total",
			run: func(reg *selfmetrics.Registry) (IntegrityStats, error) {
				c := NewOTLPLogConsumer(nil, otelstore.NewMemory(), testLogger()).WithMetrics(reg)
				err := c.handle(ctx, garbage)
				return c.IntegrityStats(), err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := selfmetrics.New("test", "abc")
			stats, err := tc.run(reg)
			if err != nil {
				t.Fatalf("malformed payload must not error the stream: %v", err)
			}
			if stats.Received != 1 || stats.Malformed != 1 || stats.Stored != 0 {
				t.Fatalf("ledger stats = %+v, want received=1 malformed=1 stored=0", stats)
			}
			if got := reg.Counter(tc.metricName, "").Value(); got != 1 {
				t.Fatalf("%s = %d, want 1", tc.metricName, got)
			}
		})
	}
}

func TestOTLPUnsupportedMetricsAreInIntegrityLedger(t *testing.T) {
	reg := selfmetrics.New("test", "abc")
	mem := tsdb.NewMemory()
	c := NewOTLPConsumer(nil, mem, testLogger()).WithMetrics(reg)
	now := uint64(time.Now().UnixNano())

	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("probectl.tenant.id", "t-ledger")}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{
					{Name: "fixture.summary", Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{
						DataPoints: []*metricspb.SummaryDataPoint{{TimeUnixNano: now, Count: 1, Sum: 1}},
					}}},
					{Name: "fixture.exponential", Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{
						DataPoints: []*metricspb.ExponentialHistogramDataPoint{{TimeUnixNano: now, Count: 1}},
					}}},
				},
			}},
		}},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handle(context.Background(), bus.Message{Key: bus.TenantKey("t-ledger", "a"), Value: payload}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if c.Consumed() != 0 || mem.Len() != 0 {
		t.Fatalf("unsupported-only payload must not be counted/stored: consumed=%d len=%d", c.Consumed(), mem.Len())
	}
	stats := c.IntegrityStats()
	if stats.Received != 1 || stats.Unsupported != 2 || stats.Stored != 0 {
		t.Fatalf("ledger stats = %+v, want received=1 unsupported=2 stored=0", stats)
	}
	if got := reg.Counter("probectl_pipeline_otlp_metrics_unsupported_total", "").Value(); got != 2 {
		t.Fatalf("unsupported metric counter = %d, want 2", got)
	}
}
