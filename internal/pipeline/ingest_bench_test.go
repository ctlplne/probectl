package pipeline

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// Consumer hot-path benchmarks (Sprint 14; feeds the Sprint 17 scale runs).
// Run: go test -bench=BenchmarkIngest -benchmem ./internal/pipeline/...

func benchResultMsg(b *testing.B) bus.Message {
	b.Helper()
	r := &resultv1.Result{
		TenantId: "t-bench", AgentId: "agent-bench", CanaryType: "http",
		ServerAddress: "https://example.com", Success: true,
		DurationNano: 123_000_000,
		Metrics:      map[string]float64{"http.ttfb_ms": 42, "http.status": 200},
	}
	v, err := proto.Marshal(r)
	if err != nil {
		b.Fatal(err)
	}
	return bus.Message{Key: []byte("t-bench"), Value: v}
}

// nullWriter accepts everything (isolates decode/convert from store latency).
type nullWriter struct{}

func (nullWriter) Write(context.Context, []tsdb.Series) error { return nil }
func (nullWriter) Close() error                               { return nil }

// BenchmarkIngestHandleLane is the full per-message consume path: decode →
// convert → (null) write, single-threaded — the SCALE-001 baseline.
func BenchmarkIngestHandleLane(b *testing.B) {
	c := NewConsumer(nil, nullWriter{}, "bench", testLogger())
	msg := benchResultMsg(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.handleLane(ctx, msg, topicGroup{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIngestHandleLaneParallel is the same path under RunParallel — what
// the key-sharded bus dispatch (PROBECTL_BUS_WORKERS) unlocks per core.
func BenchmarkIngestHandleLaneParallel(b *testing.B) {
	c := NewConsumer(nil, nullWriter{}, "bench", testLogger())
	msg := benchResultMsg(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			if err := c.handleLane(ctx, msg, topicGroup{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkIngestDecodeOnceFanout models SCALE-013: one decode feeding six
// typed sinks vs six independent decodes of the same bytes.
func BenchmarkIngestDecodeOnceFanout(b *testing.B) {
	msg := benchResultMsg(b)
	sink := func(*resultv1.Result) { /* derived-cache work is out of scope */ }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var r resultv1.Result
		if err := proto.Unmarshal(msg.Value, &r); err != nil {
			b.Fatal(err)
		}
		for s := 0; s < 6; s++ {
			sink(&r)
		}
	}
}

// BenchmarkIngestDecodePerConsumer is the pre-fan behavior: every sidecar
// unmarshals independently (the 6× multiplier the fan removes).
func BenchmarkIngestDecodePerConsumer(b *testing.B) {
	msg := benchResultMsg(b)
	sink := func(*resultv1.Result) {}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < 6; s++ {
			var r resultv1.Result
			if err := proto.Unmarshal(msg.Value, &r); err != nil {
				b.Fatal(err)
			}
			sink(&r)
		}
	}
}
