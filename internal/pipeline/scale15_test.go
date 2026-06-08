package pipeline

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// ── SCALE-003: the limiter is BOUNDED — idle identities evict ───────────────

func TestCardinalityEvictionBoundsMemory(t *testing.T) {
	base := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	now := base
	l := NewCardinalityLimiter(100, 1000).WithIdleTTL(10 * time.Minute)
	l.now = func() time.Time { return now }

	mk := func(name string) []tsdb.Series {
		return []tsdb.Series{{Metric: name, Labels: map[string]string{"k": "v"}, Value: 1}}
	}
	// Fill 50 identities for agent-1.
	for i := 0; i < 50; i++ {
		if got, _ := l.Filter("t-a", "agent-1", mk("m"+strconv.Itoa(i))); len(got) != 1 {
			t.Fatalf("fill %d rejected", i)
		}
	}
	if s := l.Stats(); s.ActiveSeries != 50 {
		t.Fatalf("active = %d, want 50", s.ActiveSeries)
	}

	// One series stays LIVE (refreshed); the rest go idle past the TTL.
	now = base.Add(5 * time.Minute)
	if got, _ := l.Filter("t-a", "agent-1", mk("m0")); len(got) != 1 {
		t.Fatal("live series rejected")
	}
	now = base.Add(16 * time.Minute) // 49 idle > 10m; m0 idle 11m... refresh m0 again first
	// keep m0 alive within TTL
	now = base.Add(12 * time.Minute)
	if got, _ := l.Filter("t-a", "agent-1", mk("m0")); len(got) != 1 {
		t.Fatal("live series rejected on refresh")
	}
	now = base.Add(18 * time.Minute) // others idle 18m > TTL; m0 idle 6m
	l.Filter("t-a", "agent-1", mk("m0"))

	s := l.Stats()
	if s.ActiveSeries != 1 {
		t.Fatalf("after eviction active = %d, want 1 (only the live series)", s.ActiveSeries)
	}
	if s.Evicted < 49 {
		t.Fatalf("evicted = %d, want >= 49", s.Evicted)
	}

	// Evicted slots are REUSABLE: new identities admit again under the cap.
	if got, _ := l.Filter("t-a", "agent-1", mk("fresh")); len(got) != 1 {
		t.Fatal("slot freed by eviction was not reusable")
	}

	// A tenant that disappears entirely is removed (no leak across churn).
	now = now.Add(time.Hour)
	l.Filter("t-other", "a", mk("x")) // trigger a sweep via another tenant
	l.mu.Lock()
	_, exists := l.tenants["t-a"]
	l.mu.Unlock()
	if exists {
		t.Fatal("fully-idle tenant entry was not evicted")
	}
}

// ── SCALE-004: bounded by DEFAULT — unlimited is the explicit opt-in ─────────

func TestRateLimitDefaultsBounded(t *testing.T) {
	def := fairness.DefaultPolicy()
	if def.ResultsPerSec <= 0 || def.FlowEventsPerSec <= 0 ||
		def.IngestBytesPerSec <= 0 || def.DeviceMetricsPerSec <= 0 {
		t.Fatalf("every ingest plane must ship a bounded default: %+v", def)
	}

	// A tenant pushed past the default cap is THROTTLED (shed, counted).
	g := fairness.NewGate(def, nil)
	ctx := context.Background()
	shed := 0
	for i := 0; i < int(def.ResultsPerSec*def.BurstSeconds)+1000; i++ {
		if !g.AdmitN(ctx, "t-hot", fairness.MeterResults, 1) {
			shed++
		}
	}
	if shed == 0 {
		t.Fatal("default policy admitted an unbounded burst (fail-open regression, SCALE-004)")
	}

	// Explicit opt-out: a NEGATIVE rate is unlimited.
	unlimited := fairness.NewGate(fairness.Policy{ResultsPerSec: -1, BurstSeconds: 1}, nil)
	for i := 0; i < 100000; i++ {
		if !unlimited.AdmitN(ctx, "t-free", fairness.MeterResults, 1) {
			t.Fatal("negative rate must mean explicit unlimited")
		}
	}
}

// s15Writer counts written series (the isolation-tagged captureWriter is not
// visible in the untagged build).
type s15Writer struct {
	mu sync.Mutex
	n  int
}

func (w *s15Writer) Write(_ context.Context, s []tsdb.Series) error {
	w.mu.Lock()
	w.n += len(s)
	w.mu.Unlock()
	return nil
}
func (w *s15Writer) Close() error { return nil }
func (w *s15Writer) count() int   { w.mu.Lock(); defer w.mu.Unlock(); return w.n }

// ── SCALE-005: the device plane is rate-bounded AND cardinality-capped ──────

func TestDeviceRateLimitAndCardinality(t *testing.T) {
	ctx := context.Background()

	// Rate: a device burst past the cap is shed before conversion/write.
	w := &s15Writer{}
	gate := fairness.NewGate(fairness.Policy{DeviceMetricsPerSec: 10, BurstSeconds: 1}, nil)
	c := NewDeviceConsumer(nil, w, testLogger()).WithFairness(gate)
	mkBatch := func(n int, namePrefix string) bus.Message {
		ms := make([]*devicev1.DeviceMetric, n)
		for i := range ms {
			ms[i] = &devicev1.DeviceMetric{TenantId: "t-d", AgentId: "ag-1",
				Name: fmt.Sprintf("probectl.device.%s.%d", namePrefix, i), Value: 1}
		}
		v, _ := proto.Marshal(&devicev1.DeviceMetricBatch{Metrics: ms})
		return bus.Message{Key: []byte("t-d"), Value: v}
	}
	if err := c.handleLane(ctx, mkBatch(10, "ok"), ""); err != nil {
		t.Fatal(err)
	}
	if w.count() == 0 {
		t.Fatal("within-cap device batch must write")
	}
	// Burst far past the cap across several batches: the bucket's deficit
	// semantics admit at most one in-flight overshoot, then SHED. Total
	// written stays bounded near the cap, nowhere near the offered load.
	for i := 0; i < 10; i++ {
		if err := c.handleLane(ctx, mkBatch(100, fmt.Sprintf("burst%d", i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	if c.shed.Load() == 0 {
		t.Fatal("over-cap device burst was never shed (SCALE-005); shed must be counted")
	}
	if w.count() > 10+100 { // first batch + at most one deficit overshoot
		t.Fatalf("throttling failed: %d series written of 1010 offered", w.count())
	}

	// Cardinality: identities past the per-agent cap reject per-series.
	w2 := &s15Writer{}
	c2 := NewDeviceConsumer(nil, w2, testLogger())
	c2.card = NewCardinalityLimiter(5, 1000)
	if err := c2.handleLane(ctx, mkBatch(50, "card"), ""); err != nil {
		t.Fatal(err)
	}
	if w2.count() != 5 {
		t.Fatalf("device cardinality cap admitted %d series, want 5", w2.count())
	}
}

// ── SCALE-007: a large tenant spreads across partitions; per-agent FIFO holds ─

func TestPartitionTenantKeySpreads(t *testing.T) {
	buckets := map[string]bool{}
	for i := 0; i < 200; i++ {
		k := string(bus.TenantKey("big-tenant", fmt.Sprintf("agent-%d", i)))
		buckets[k] = true
	}
	if len(buckets) < 4 {
		t.Fatalf("200 agents landed on %d key(s) — hot partition remains", len(buckets))
	}
	// Stability: the SAME agent always gets the SAME key (per-agent FIFO).
	a := bus.TenantKey("big-tenant", "agent-7")
	b := bus.TenantKey("big-tenant", "agent-7")
	if string(a) != string(b) {
		t.Fatal("agent key not stable — per-agent ordering would break")
	}
	// No entropy = the plain tenant key (single-writer planes keep total order).
	if string(bus.TenantKey("t", "")) != "t" {
		t.Fatal("empty entropy must keep the plain tenant key")
	}
}

// ── SCALE-011: enrichment is async — misses never block, hits enrich free ───

// slowEnricher simulates a slow upstream (the DNS-lookup path).
type slowEnricher struct {
	delay time.Duration
	mu    sync.Mutex
	calls int
}

func (s *slowEnricher) Enrich(ctx context.Context, ip string) (opendata.Enrichment, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return opendata.Enrichment{}, ctx.Err()
	}
	return opendata.Enrichment{ASN: 64500, ASName: "TEST-NET", CountryCode: "ZZ"}, nil
}

func TestEnrichAsyncNeverBlocksHotPath(t *testing.T) {
	inner := &slowEnricher{delay: 50 * time.Millisecond}
	a := NewAsyncEnricher(inner, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	// MISS: returns immediately (pending), far faster than the inner delay.
	start := time.Now()
	_, err := a.Enrich(ctx, "8.8.8.8")
	if err == nil {
		t.Fatal("first lookup must report pending (warming)")
	}
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("miss blocked the hot path for %v", d)
	}

	// After the background warm, the SAME address enriches inline.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if e, err := a.Enrich(ctx, "8.8.8.8"); err == nil {
			if e.ASN != 64500 {
				t.Fatalf("warmed enrichment wrong: %+v", e)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cache never warmed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// LAG: flooding distinct addresses sheds warm requests (counted), and
	// every call still returns instantly.
	for i := 0; i < 5000; i++ {
		_, _ = a.Enrich(ctx, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	_, misses, dropped := a.EnrichStats()
	if misses == 0 || dropped == 0 {
		t.Fatalf("lagging enrichment must shed warms: misses=%d dropped=%d", misses, dropped)
	}
}

// BenchmarkEnrichAsyncHit is the steady-state hot path: a cache hit.
func BenchmarkEnrichAsyncHit(b *testing.B) {
	inner := &slowEnricher{delay: 0}
	a := NewAsyncEnricher(inner, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	_, _ = a.Enrich(ctx, "1.1.1.1")
	for i := 0; i < 100 && func() bool { _, err := a.Enrich(ctx, "1.1.1.1"); return err != nil }(); i++ {
		time.Sleep(time.Millisecond)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Enrich(ctx, "1.1.1.1"); err != nil {
			b.Fatal("hit path returned pending")
		}
	}
}

// BenchmarkEnrichSyncMiss is what every cache miss used to cost INLINE.
func BenchmarkEnrichSyncMiss(b *testing.B) {
	inner := &slowEnricher{delay: time.Millisecond}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inner.Enrich(ctx, "9.9.9.9")
	}
}
