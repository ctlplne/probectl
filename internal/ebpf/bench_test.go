package ebpf

// Agent overhead benchmarks (U-051): reproducible numbers behind the
// "lightweight" claim. What runs here is the agent's USERSPACE pipeline —
// Observe → ServiceMap → Drain → protobuf → bus publish — under a defined
// synthetic traffic profile (the same shape the recorded fixtures replay).
// The kernel/ring-buffer side needs a live kernel and is measured on
// reference hosts with the same methodology (docs/agent-overhead.md); the
// kernel-matrix CI job proves that path loads, this file prices the rest.
//
// TestAgentOverheadReport runs in every `make test` and FAILS below a
// conservative throughput floor — a 20x pipeline regression cannot land
// silently. The floor is deliberately loose (CI runners are shared and
// -race runs ~10x slower); the real numbers go in docs/agent-overhead.md.

import (
	"context"
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// trafficProfile is the defined synthetic shape: a host talking to a
// bounded service fan-out (50 peers × 8 ports), mixed ingress/egress —
// realistic ServiceMap cardinality rather than a degenerate single edge.
func trafficProfile(i int) Flow {
	dir := "egress"
	if i%3 == 0 {
		dir = "ingress"
	}
	return Flow{
		TenantID:    "bench",
		AgentID:     "agent-bench",
		Host:        "host-bench",
		Observed:    time.Unix(1700000000+int64(i%600), 0),
		Source:      Endpoint{Address: fmt.Sprintf("10.0.%d.%d", i%4, i%200), Port: uint32(30000 + i%2000), PID: uint32(1000 + i%64), Process: "bench-client"},
		Destination: Endpoint{Address: fmt.Sprintf("10.1.0.%d", i%50), Port: uint32(8000 + i%8), Process: "bench-server"},
		Transport:   "tcp",
		NetworkType: "ipv4",
		Bytes:       uint64(512 + i%4096),
		Packets:     uint64(1 + i%16),
		Direction:   dir,
		State:       "established",
	}
}

// drainEvery mirrors the agent's flush cadence at high rate.
const drainEvery = 4096

func BenchmarkAggregatorObserve(b *testing.B) {
	a := NewAggregator()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a.Observe(trafficProfile(i))
		if i%drainEvery == drainEvery-1 {
			a.Drain()
		}
	}
}

func BenchmarkPipelineObserveDrainEmit(b *testing.B) {
	mem := bus.NewMemory()
	defer mem.Close()
	em := NewBusEmitter(mem, "bench")
	a := NewAggregator()
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a.Observe(trafficProfile(i))
		if i%drainEvery == drainEvery-1 {
			flows, edges := a.Drain()
			if err := em.Emit(ctx, flows, edges, nil); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkRedactPayloadHeaders(b *testing.B) {
	payload := []byte("POST /api/v1/orders HTTP/1.1\r\nHost: shop.internal\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n" +
		string(make([]byte, 1024)))
	buf := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copy(buf, payload)
		RedactPayload(buf, RedactHeaders)
	}
}

// TestAgentOverheadReport is the CI smoke + the methodology's measured
// numbers: it pushes a fixed profile through the full userspace pipeline
// and reports throughput, CPU time, and memory — failing below a floor so
// the "lightweight" claim has a tripwire, not just adjectives.
func TestAgentOverheadReport(t *testing.T) {
	const events = 200_000

	mem := bus.NewMemory()
	defer mem.Close()
	em := NewBusEmitter(mem, "bench")
	a := NewAggregator()
	ctx := context.Background()

	var ruStart, ruEnd syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ruStart); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < events; i++ {
		a.Observe(trafficProfile(i))
		if i%drainEvery == drainEvery-1 {
			flows, edges := a.Drain()
			if err := em.Emit(ctx, flows, edges, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	flows, edges := a.Drain()
	_ = em.Emit(ctx, flows, edges, nil)
	wall := time.Since(start)
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ruEnd); err != nil {
		t.Fatal(err)
	}

	cpu := time.Duration(ruEnd.Utime.Nano()-ruStart.Utime.Nano()) +
		time.Duration(ruEnd.Stime.Nano()-ruStart.Stime.Nano())
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	eps := float64(events) / wall.Seconds()
	usPerEvent := cpu.Seconds() / float64(events) * 1e6
	t.Logf("AGENT OVERHEAD (userspace pipeline, %d events, profile: 50 peers × 8 ports): "+
		"%.0f events/s wall; %.2f µs CPU/event (%.2fs CPU total); heap_inuse=%.1f MiB sys=%.1f MiB; maxrss=%d KiB",
		events, eps, usPerEvent, cpu.Seconds(),
		float64(ms.HeapInuse)/(1<<20), float64(ms.Sys)/(1<<20), ruEnd.Maxrss)
	t.Logf("at 1k flows/s this CPU cost is ~%.3f%% of one core", usPerEvent*1000/1e6*100)

	// The tripwire: conservatively low (shared runners, -race in make test
	// runs ~10x slower than plain builds). A healthy build does hundreds of
	// thousands of events/s; falling under 20k/s means the pipeline got at
	// least ~20x slower — that is a regression, not noise.
	if eps < 20_000 {
		t.Fatalf("userspace pipeline throughput %.0f events/s is below the 20k floor — the 'lightweight' claim regressed (U-051)", eps)
	}
}
