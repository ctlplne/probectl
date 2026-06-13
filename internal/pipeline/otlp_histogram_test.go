// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// ARCH-006: an OTLP explicit-bucket histogram converts to the Prometheus
// _bucket{le}/_sum/_count triple with CUMULATIVE bucket counts and a +Inf
// bucket — so histogram_quantile() works instead of the data being dropped.
func TestHistogramConversion(t *testing.T) {
	c := NewOTLPConsumer(nil, tsdb.NewMemory(), testLogger())
	now := uint64(time.Now().UnixNano())
	dp := &metricspb.HistogramDataPoint{
		TimeUnixNano:   now,
		Count:          6,
		Sum:            proto64(13.5),
		ExplicitBounds: []float64{1, 5},   // 2 bounds → 3 buckets
		BucketCounts:   []uint64{2, 3, 1}, // le1=2, le5=2+3=5, le+Inf=6
	}
	series := c.histogramSeries("request.latency", []*metricspb.HistogramDataPoint{dp}, "t-a", map[string]string{}, false)

	byKey := map[string]float64{}
	for _, s := range series {
		k := s.Metric
		if le, ok := s.Labels["le"]; ok {
			k += "{le=" + le + "}"
		}
		byKey[k] = s.Value
		if s.Labels["tenant_id"] != "t-a" {
			t.Fatalf("series %s missing tenant label", s.Metric)
		}
		if _, tagged := s.Labels["otel_temporality"]; tagged {
			t.Errorf("cumulative histogram series %s wrongly tagged delta", s.Metric)
		}
	}
	want := map[string]float64{
		"probectl_otlp_request_latency_bucket{le=1}":    2,
		"probectl_otlp_request_latency_bucket{le=5}":    5, // cumulative
		"probectl_otlp_request_latency_bucket{le=+Inf}": 6, // cumulative total
		"probectl_otlp_request_latency_count":           6,
		"probectl_otlp_request_latency_sum":             13.5,
	}
	for k, v := range want {
		if byKey[k] != v {
			t.Errorf("%s = %v, want %v", k, byKey[k], v)
		}
	}
}

// CORRECT-008: a DELTA histogram is NOT cumulative-over-time. The converter must
// tag every emitted series (buckets, _sum, _count) otel_temporality="delta" so a
// query never rate()s it as if it were a monotonic cumulative histogram. A
// CUMULATIVE histogram (the case above) stays untagged. This proves the
// temporality is honored rather than silently misread as cumulative.
func TestHistogramConversionDeltaTemporality(t *testing.T) {
	c := NewOTLPConsumer(nil, tsdb.NewMemory(), testLogger())
	now := uint64(time.Now().UnixNano())
	dp := &metricspb.HistogramDataPoint{
		TimeUnixNano:   now,
		Count:          6,
		Sum:            proto64(13.5),
		ExplicitBounds: []float64{1, 5},
		BucketCounts:   []uint64{2, 3, 1},
	}
	// Drive the real conversion entry point so the temporality branch is exercised.
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{
					Name: "request.latency",
					Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
						AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
						DataPoints:             []*metricspb.HistogramDataPoint{dp},
					}},
				}},
			}},
		}},
	}
	series := c.convert(req, "t-a")
	if len(series) == 0 {
		t.Fatal("delta histogram produced no series")
	}
	for _, s := range series {
		if s.Labels["otel_temporality"] != "delta" {
			t.Errorf("delta histogram series %s not tagged otel_temporality=delta (labels=%v)", s.Metric, s.Labels)
		}
	}
}

func proto64(f float64) *float64 { return &f }
