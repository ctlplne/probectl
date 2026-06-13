// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"fmt"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// floodReq builds an OTLP metrics request with n unique-attribute gauge points
// for a tenant (each a distinct series identity → cardinality pressure).
func floodReq(tenant string, n int) bus.Message {
	now := uint64(time.Now().UnixNano())
	dps := make([]*metricspb.NumberDataPoint, 0, n)
	for i := 0; i < n; i++ {
		dps = append(dps, &metricspb.NumberDataPoint{
			TimeUnixNano: now,
			Attributes:   []*commonpb.KeyValue{kv("uniq", fmt.Sprintf("%d", i))},
			Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: float64(i)},
		})
	}
	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				kv("probectl.tenant.id", tenant),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{
					{Name: "flood", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: dps}}},
				},
			}},
		}},
	}
	payload, _ := proto.Marshal(req)
	return bus.Message{Key: bus.TenantKey(tenant, "x"), Value: payload}
}

// TestOTLPCardinalityCapAndFairness is the SCALE-003 acceptance test: a tenant
// flooding the OTLP metrics plane with unique-attribute series is capped (by
// the per-tenant cardinality cap) and shed (by the per-tenant fairness gate),
// while a second, quiet tenant is unaffected — its series store cleanly.
func TestOTLPCardinalityCapAndFairness(t *testing.T) {
	mem := tsdb.NewMemory()

	// Per-tenant OTLP rate is small; cardinality cap is small. Both planes
	// must clamp the flooder without touching the quiet tenant.
	gate := fairness.NewGate(fairness.Policy{OTLPSeriesPerSec: 100, BurstSeconds: 1}, nil)
	c := NewOTLPConsumer(nil, mem, testLogger()).
		WithFairness(gate).
		WithCardinalityCaps(500) // per-tenant distinct series cap

	const flood = 5000
	// Flooder: push way more unique series than either bound allows, twice.
	for i := 0; i < 2; i++ {
		if err := c.handle(context.Background(), floodReq("noisy", flood)); err != nil {
			t.Fatalf("flood handle: %v", err)
		}
	}

	// The flooder must be bounded: stored series stay under the cardinality cap,
	// and fairness must have shed at least some of the over-rate series.
	noisyStored := len(mem.Query("probectl_otlp_flood", map[string]string{"tenant_id": "noisy"}))
	if noisyStored == 0 {
		t.Fatalf("expected SOME noisy series to store (cap is not zero); got 0")
	}
	if noisyStored > 500 {
		t.Fatalf("noisy tenant stored %d series, want <= cardinality cap 500", noisyStored)
	}
	if c.Shed() == 0 {
		t.Fatalf("fairness gate shed nothing for a tenant flooding %d series at a 100/s bound", 2*flood)
	}

	// Quiet tenant: a small, in-bounds push stores cleanly and is NOT starved.
	if err := c.handle(context.Background(), floodReq("quiet", 10)); err != nil {
		t.Fatalf("quiet handle: %v", err)
	}
	quietStored := len(mem.Query("probectl_otlp_flood", map[string]string{"tenant_id": "quiet"}))
	if quietStored != 10 {
		t.Fatalf("quiet tenant stored %d/10 series — starved by the noisy neighbor (isolation broken)", quietStored)
	}
}
