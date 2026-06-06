package tsdb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func sampleAt(t time.Time, metric string) Series {
	return Series{Metric: metric, Labels: map[string]string{"tenant_id": "t"}, Value: 1, TimeMillis: t.UnixMilli()}
}

// U-018: samples that ARRIVED before the retention window are swept on the
// next write (arrival-based: backfilled sample timestamps are never swept
// early — the writer is a recency buffer).
func TestMemoryRetentionWindowSweeps(t *testing.T) {
	m := NewMemoryWithLimits(time.Hour, 1<<30)
	now := time.Unix(100000, 0)
	m.now = func() time.Time { return now }

	_ = m.Write(context.Background(), []Series{sampleAt(now.Add(-48*time.Hour), "old")}) // historic TIMESTAMP, fresh arrival
	if m.Len() != 1 {
		t.Fatal("backfilled sample must not be swept by its own timestamp")
	}

	now = now.Add(2 * time.Hour) // its ARRIVAL ages past the window
	_ = m.Write(context.Background(), []Series{sampleAt(now, "fresh")})
	if got := m.Len(); got != 1 {
		t.Fatalf("retained = %d, want the aged arrival swept", got)
	}
	if u := m.Usage(); u.EvictedAge != 1 || u.Samples != 1 {
		t.Fatalf("usage = %+v", u)
	}
	if len(m.Query("fresh", nil)) != 1 || len(m.Query("old", nil)) != 0 {
		t.Fatal("wrong sample survived")
	}
}

// U-018: the byte wall evicts OLDEST-FIRST and usage accounting stays exact.
func TestMemoryByteWallEvictsOldestFirst(t *testing.T) {
	one := sampleSize(sampleAt(time.Unix(0, 0), "m_000"))
	m := NewMemoryWithLimits(24*time.Hour, one*10) // room for ~10 samples
	now := time.Unix(100000, 0)
	m.now = func() time.Time { return now }

	for i := 0; i < 30; i++ {
		_ = m.Write(context.Background(), []Series{sampleAt(now, fmt.Sprintf("m_%03d", i))})
	}
	u := m.Usage()
	if u.Bytes > one*10 {
		t.Fatalf("bytes = %d, above the wall %d", u.Bytes, one*10)
	}
	if u.EvictedBytes == 0 {
		t.Fatal("the wall never evicted")
	}
	if len(m.Query("m_000", nil)) != 0 {
		t.Fatal("oldest sample survived eviction")
	}
	if len(m.Query("m_029", nil)) != 1 {
		t.Fatal("newest sample was evicted")
	}
}

// U-018 soak (time-compressed): a steady write load against a small wall
// PLATEAUS — retained bytes/samples stop growing instead of climbing forever.
func TestMemorySoakPlateaus(t *testing.T) {
	wall := int64(64 << 10) // 64 KiB
	m := NewMemoryWithLimits(time.Hour, wall)
	now := time.Unix(100000, 0)
	m.now = func() time.Time { return now }

	var peak int64
	for hour := 0; hour < 48; hour++ { // two compressed days
		now = now.Add(time.Hour / 4)
		for i := 0; i < 200; i++ {
			_ = m.Write(context.Background(), []Series{sampleAt(now, fmt.Sprintf("soak_%d", i%50))})
		}
		if u := m.Usage(); u.Bytes > peak {
			peak = u.Bytes
		}
	}
	final := m.Usage()
	if final.Bytes > wall {
		t.Fatalf("final bytes %d above the wall %d", final.Bytes, wall)
	}
	if peak > wall+wall/10 {
		t.Fatalf("peak %d overshot the wall %d — no plateau", peak, wall)
	}
	if final.EvictedAge == 0 && final.EvictedBytes == 0 {
		t.Fatal("a 48h soak must have evicted something")
	}
}

// DeleteTenant keeps the byte accounting exact (S-T5 erasure + U-018).
func TestMemoryDeleteTenantAccounting(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	_ = m.Write(context.Background(), []Series{sampleAt(now, "a"), sampleAt(now, "b")})
	if _, err := m.DeleteTenant(context.Background(), "t"); err != nil {
		t.Fatal(err)
	}
	if u := m.Usage(); u.Samples != 0 || u.Bytes != 0 {
		t.Fatalf("usage after erasure = %+v, want zeroed accounting", u)
	}
}
