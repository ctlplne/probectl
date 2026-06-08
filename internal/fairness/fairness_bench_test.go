package fairness

import (
	"context"
	"strconv"
	"testing"
)

// BenchmarkAdmitNParallel measures admit throughput under high tenant fan-in —
// the contention SCALE-001 addressed. Each goroutine cycles through many
// tenants so admissions land on different shards; before sharding, every
// admit (any tenant) serialized on one process-wide mutex. This is the
// regression guard for the admit hot path.
func BenchmarkAdmitNParallel(b *testing.B) {
	g := NewGate(DefaultPolicy(), nil)
	const tenants = 256
	ids := make([]string, tenants)
	for i := range ids {
		ids[i] = "tenant-" + strconv.Itoa(i)
	}
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			g.AdmitN(ctx, ids[i%tenants], MeterResults, 1)
			i++
		}
	})
}

// BenchmarkAdmitNSingleTenant is the worst case the shard CANNOT help: all
// load on one tenant (one shard). It documents that single-tenant admit cost
// is unchanged (the per-tenant critical section is the same as before).
func BenchmarkAdmitNSingleTenant(b *testing.B) {
	g := NewGate(DefaultPolicy(), nil)
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			g.AdmitN(ctx, "tenant-hot", MeterResults, 1)
		}
	})
}
