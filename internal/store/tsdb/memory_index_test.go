// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tsdb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// SCALE-014: Query touches only the named metric's samples — correctness
// across writes, retention eviction, and tenant erasure.
func TestTSDBIndexedQueryAcrossEviction(t *testing.T) {
	base := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	now := base
	m := NewMemoryWithLimits(10*time.Minute, 1<<30)
	m.now = func() time.Time { return now }
	ctx := context.Background()

	write := func(metric, tenant string, v float64) {
		_ = m.Write(ctx, []Series{{Metric: metric, Labels: map[string]string{"tenant_id": tenant}, Value: v}})
	}
	write("cpu", "t-a", 1)
	write("mem", "t-a", 2)
	write("cpu", "t-b", 3)

	if got := m.Query("cpu", nil); len(got) != 2 {
		t.Fatalf("cpu = %d, want 2", len(got))
	}
	if got := m.Query("cpu", map[string]string{"tenant_id": "t-b"}); len(got) != 1 || got[0].Value != 3 {
		t.Fatalf("matched cpu = %+v", got)
	}
	if got := m.Query("absent", nil); len(got) != 0 {
		t.Fatalf("absent metric returned %d", len(got))
	}

	// Retention evicts the OLD samples; the index follows (no stale reads,
	// no panics from shifted positions).
	now = base.Add(11 * time.Minute)
	write("cpu", "t-a", 9) // triggers enforce; the first three age out
	if got := m.Query("cpu", nil); len(got) != 1 || got[0].Value != 9 {
		t.Fatalf("post-eviction cpu = %+v", got)
	}
	if got := m.Query("mem", nil); len(got) != 0 {
		t.Fatalf("evicted metric still indexed: %+v", got)
	}

	// Tenant erasure rebuilds the index correctly.
	write("cpu", "t-b", 5)
	if _, err := m.DeleteTenant(ctx, "t-a"); err != nil {
		t.Fatal(err)
	}
	if got := m.Query("cpu", nil); len(got) != 1 || got[0].Value != 5 {
		t.Fatalf("post-erasure cpu = %+v", got)
	}
}

// BenchmarkTSDBQueryIndexed: query ONE metric among many — the SCALE-014
// shape (the old scan walked every retained sample).
func BenchmarkTSDBQueryIndexed(b *testing.B) {
	m := NewMemoryWithLimits(time.Hour, 1<<30)
	ctx := context.Background()
	for i := 0; i < 200; i++ { // 200 metrics × 50 samples = 10k samples
		metric := fmt.Sprintf("metric_%d", i)
		for j := 0; j < 50; j++ {
			_ = m.Write(ctx, []Series{{Metric: metric, Labels: map[string]string{"tenant_id": "t"}, Value: float64(j)}})
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := m.Query("metric_42", nil); len(got) != 50 {
			b.Fatalf("got %d", len(got))
		}
	}
}
