package pathstore

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/path"
)

// Path-store write benchmarks (Sprint 17, SCALE-015 — the named missing
// hot-path bench). The discovery write is the per-traceroute cost; the
// batched variant is what production pays after Sprint 14's cross-path
// window. Run: go test -bench=BenchmarkPathStoreWrite -benchmem ./internal/store/pathstore/
func benchPath(hops int) *path.Path {
	p := &path.Path{Target: "dst.example", TargetIP: "203.0.113.9", Mode: "icmp", MaxHops: hops}
	for ttl := 1; ttl <= hops; ttl++ {
		p.Hops = append(p.Hops, path.Hop{TTL: ttl, Nodes: []path.HopNode{{
			IP: fmt.Sprintf("10.0.%d.%d", ttl/256, ttl%256), Sent: 3, Received: 3,
			RTTMinMs: 1.1, RTTAvgMs: 1.8, RTTMaxMs: 3.2,
		}}})
		if ttl > 1 {
			p.Links = append(p.Links, path.Link{TTL: ttl, From: fmt.Sprintf("10.0.%d.%d", (ttl-1)/256, (ttl-1)%256), To: fmt.Sprintf("10.0.%d.%d", ttl/256, ttl%256)})
		}
	}
	return p
}

// BenchmarkPathStoreWrite is one discovery → store (the pre-S14 unit cost).
func BenchmarkPathStoreWrite(b *testing.B) {
	st := NewMemory()
	p := benchPath(16) // a typical internet path depth
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.Save(ctx, "t-bench", p); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPathStoreWriteBatched is the production shape: Saves enqueue into
// the Sprint 14 cross-path window and flush in combined batches.
func BenchmarkPathStoreWriteBatched(b *testing.B) {
	inner := NewMemory()
	bs := NewBatchingSaver(inner, slog.New(slog.NewTextHandler(io.Discard, nil)), 50*time.Millisecond, 32)
	p := benchPath(16)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bs.Save(ctx, "t-bench", p); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	bs.Flush(ctx)
	if bs.Lost() != 0 {
		b.Fatalf("batched writes lost %d", bs.Lost())
	}
}
