// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// CORRECT-006: the far-future clock-skew clamp must cover EVERY ingest path, not
// just native results + device. Before the fix it was wired only at
// convert.go + device.go; OTLP metrics/histograms/traces/logs and flow landed a
// +1h timestamp verbatim, poisoning range queries and "latest" views. Each
// sub-test pushes a timestamp 1h in the future through the REAL converter and
// asserts (a) the stored event time is clamped to ~now and (b) the shared
// FutureClamped counter advanced (one clamp, one /metrics surface).
func TestFutureClampAcrossIngestPaths(t *testing.T) {
	const slack = 2 * time.Minute // well under the 5m MaxFutureSkew bound

	t.Run("otlp_number", func(t *testing.T) {
		c := NewOTLPConsumer(nil, tsdb.NewMemory(), testLogger())
		future := uint64(time.Now().Add(time.Hour).UnixNano())
		before := FutureClamped()
		req := &colmetricspb.ExportMetricsServiceRequest{
			ResourceMetrics: []*metricspb.ResourceMetrics{{
				ScopeMetrics: []*metricspb.ScopeMetrics{{
					Metrics: []*metricspb.Metric{{
						Name: "q.depth",
						Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
							DataPoints: []*metricspb.NumberDataPoint{{
								TimeUnixNano: future,
								Value:        &metricspb.NumberDataPoint_AsInt{AsInt: 1},
							}},
						}},
					}},
				}},
			}},
		}
		series := c.convert(req, "t-a")
		if len(series) == 0 {
			t.Fatal("no series produced")
		}
		assertClampedMillis(t, series[0].TimeMillis, slack)
		if FutureClamped() <= before {
			t.Fatal("FutureClamped not incremented for OTLP number point")
		}
	})

	t.Run("otlp_histogram", func(t *testing.T) {
		c := NewOTLPConsumer(nil, tsdb.NewMemory(), testLogger())
		future := uint64(time.Now().Add(time.Hour).UnixNano())
		before := FutureClamped()
		req := &colmetricspb.ExportMetricsServiceRequest{
			ResourceMetrics: []*metricspb.ResourceMetrics{{
				ScopeMetrics: []*metricspb.ScopeMetrics{{
					Metrics: []*metricspb.Metric{{
						Name: "lat",
						Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
							DataPoints: []*metricspb.HistogramDataPoint{{
								TimeUnixNano:   future,
								Count:          1,
								ExplicitBounds: []float64{1},
								BucketCounts:   []uint64{1, 0},
							}},
						}},
					}},
				}},
			}},
		}
		series := c.convert(req, "t-a")
		if len(series) == 0 {
			t.Fatal("no histogram series produced")
		}
		for _, s := range series {
			assertClampedMillis(t, s.TimeMillis, slack)
		}
		if FutureClamped() <= before {
			t.Fatal("FutureClamped not incremented for OTLP histogram point")
		}
	})

	t.Run("otlp_span", func(t *testing.T) {
		future := uint64(time.Now().Add(time.Hour).UnixNano())
		before := FutureClamped()
		req := &coltracepb.ExportTraceServiceRequest{
			ResourceSpans: []*tracepb.ResourceSpans{{
				ScopeSpans: []*tracepb.ScopeSpans{{
					Spans: []*tracepb.Span{{
						Name:              "op",
						StartTimeUnixNano: future,
						EndTimeUnixNano:   future + uint64(time.Millisecond),
					}},
				}},
			}},
		}
		spans := convertSpans(req, "t-a")
		if len(spans) != 1 {
			t.Fatalf("want 1 span, got %d", len(spans))
		}
		assertClampedTime(t, spans[0].Start, slack)
		// Duration is preserved (computed from raw end-start, not the clamp).
		if spans[0].Duration != time.Millisecond {
			t.Fatalf("span duration corrupted by clamp: %v", spans[0].Duration)
		}
		if FutureClamped() <= before {
			t.Fatal("FutureClamped not incremented for OTLP span")
		}
	})

	t.Run("otlp_log", func(t *testing.T) {
		future := uint64(time.Now().Add(time.Hour).UnixNano())
		before := FutureClamped()
		req := &collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{{
				ScopeLogs: []*logspb.ScopeLogs{{
					LogRecords: []*logspb.LogRecord{{
						TimeUnixNano: future,
					}},
				}},
			}},
		}
		recs := convertLogs(req, "t-a")
		if len(recs) != 1 {
			t.Fatalf("want 1 log, got %d", len(recs))
		}
		assertClampedTime(t, recs[0].TS, slack)
		if FutureClamped() <= before {
			t.Fatal("FutureClamped not incremented for OTLP log")
		}
	})

	t.Run("flow", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		before := FutureClamped()
		row := rowFromProto(&flowv1.FlowRecord{
			TenantId:    "t-a",
			EndUnixNano: future.UnixNano(),
		})
		assertClampedTime(t, row.TS, slack)
		assertClampedTime(t, row.StartTS, slack)
		if FutureClamped() <= before {
			t.Fatal("FutureClamped not incremented for flow row")
		}
	})
}

func assertClampedMillis(t *testing.T, gotMillis int64, slack time.Duration) {
	t.Helper()
	max := time.Now().Add(slack).UnixMilli()
	if gotMillis > max {
		t.Fatalf("timestamp not clamped: got %d, want <= ~now (%d)", gotMillis, max)
	}
}

func assertClampedTime(t *testing.T, got time.Time, slack time.Duration) {
	t.Helper()
	if got.After(time.Now().Add(slack)) {
		t.Fatalf("timestamp not clamped: got %s, want <= ~now", got)
	}
}
