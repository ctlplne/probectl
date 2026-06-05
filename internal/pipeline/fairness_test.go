package pipeline

import (
	"context"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

type fairnessSource map[string]fairness.Policy

func (s fairnessSource) PolicyFor(_ context.Context, tenantID string) (fairness.Policy, bool, error) {
	p, ok := s[tenantID]
	return p, ok, nil
}

func primedGate(t *testing.T, src fairnessSource, tenants ...string) *fairness.Gate {
	t.Helper()
	g := fairness.NewGate(fairness.Policy{}, src).WithPolicyTTL(time.Hour)
	for _, tn := range tenants {
		g.EffectivePolicy(context.Background(), tn) // schedule the async fetch
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, tn := range tenants {
		want, ok := src[tn]
		if !ok {
			continue
		}
		for time.Now().Before(deadline) {
			got := g.EffectivePolicy(context.Background(), tn)
			if got.ResultsPerSec == want.ResultsPerSec && got.FlowEventsPerSec == want.FlowEventsPerSec {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	return g
}

// TestResultConsumerShedsByTenant: the gated result pipeline sheds the
// over-rate tenant BEFORE the TSDB write while the other tenant's results
// land — the wiring half of the backpressure-isolation story.
func TestResultConsumerShedsByTenant(t *testing.T) {
	w := tsdb.NewMemory()
	gate := primedGate(t, fairnessSource{
		"heavy": {ResultsPerSec: 5, BurstSeconds: 1}, // capacity 5
	}, "heavy", "modest")
	c := NewConsumer(bus.NewMemory(), w, "test", logging.New(io.Discard, "error", "json")).WithFairness(gate)
	ctx := context.Background()

	publish := func(tenant string, n int) {
		for range n {
			payload, err := proto.Marshal(&resultv1.Result{TenantId: tenant, AgentId: "a1", CanaryType: "noop", Success: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.handle(ctx, bus.Message{Key: []byte(tenant), Value: payload}); err != nil {
				t.Fatal(err)
			}
		}
	}
	publish("heavy", 100) // burst: only ~5 admit
	publish("modest", 20) // unbounded: all admit

	heavy := w.Query("probectl_probe_success", map[string]string{"tenant_id": "heavy"})
	modest := w.Query("probectl_probe_success", map[string]string{"tenant_id": "modest"})
	// The memory TSDB keeps the latest point per series; count via the gate's
	// accounting instead — the store-level proof is that heavy wrote SOMETHING
	// but the gate bounded it.
	if len(heavy) == 0 || len(modest) == 0 {
		t.Fatalf("both tenants must have admitted series: heavy=%d modest=%d", len(heavy), len(modest))
	}
	hs := gate.SnapshotTenant(ctx, "heavy")
	ms := gate.SnapshotTenant(ctx, "modest")
	if hc := hs.Ingest[fairness.MeterResults]; hc.AdmittedUnits > 6 || hc.ShedUnits < 94 {
		t.Fatalf("heavy must be bounded at its burst: %+v", hc)
	}
	if mc := ms.Ingest[fairness.MeterResults]; mc.ShedUnits != 0 || mc.AdmittedUnits != 20 {
		t.Fatalf("modest must be untouched: %+v", mc)
	}
}

// TestFlowConsumerShedsBatches: a flow batch over the tenant's rate is shed
// before enrichment + insert; the other tenant's batch lands in the store.
func TestFlowConsumerShedsBatches(t *testing.T) {
	st := flowstore.NewMemory()
	gate := primedGate(t, fairnessSource{
		"heavy": {FlowEventsPerSec: 10, BurstSeconds: 1}, // capacity 10
	}, "heavy", "modest")
	c := NewFlowConsumer(bus.NewMemory(), st, nil, nil).WithFairness(gate)
	ctx := context.Background()

	mkBatch := func(tenant string, rows int) bus.Message {
		flows := make([]*flowv1.FlowRecord, rows)
		end := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
		for i := range flows {
			flows[i] = &flowv1.FlowRecord{TenantId: tenant, AgentId: "a1", ExporterAddress: "203.0.113.10",
				FlowProtocol: "ipfix", EndUnixNano: end.UnixNano(), SourceAddress: "10.0.0.1",
				DestinationAddress: "10.0.0.2", BytesScaled: 1, PacketsScaled: 1, InputInterface: 1}
		}
		value, err := proto.Marshal(&flowv1.FlowBatch{Flows: flows})
		if err != nil {
			t.Fatal(err)
		}
		return bus.Message{Key: []byte(tenant), Value: value}
	}

	// Heavy: first batch (15 rows > capacity 10) admits on deficit semantics;
	// the second is shed while the deficit repays.
	if err := c.handle(ctx, mkBatch("heavy", 15)); err != nil {
		t.Fatal(err)
	}
	if err := c.handle(ctx, mkBatch("heavy", 15)); err != nil {
		t.Fatal(err)
	}
	// Modest is untouched.
	if err := c.handle(ctx, mkBatch("modest", 7)); err != nil {
		t.Fatal(err)
	}

	hs := gate.SnapshotTenant(ctx, "heavy").Ingest[fairness.MeterFlowEvents]
	if hs.AdmittedUnits != 15 || hs.ShedUnits != 15 {
		t.Fatalf("heavy flow accounting: %+v", hs)
	}
	ms := gate.SnapshotTenant(ctx, "modest").Ingest[fairness.MeterFlowEvents]
	if ms.AdmittedUnits != 7 || ms.ShedUnits != 0 {
		t.Fatalf("modest flow accounting: %+v", ms)
	}
}
