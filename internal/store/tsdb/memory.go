package tsdb

import (
	"context"
	"sync"
	"time"
)

// Bounded defaults for the in-memory writer (U-018): the lightweight mode
// previously grew without bound. Samples older than the retention window are
// swept, and a max-bytes wall evicts OLDEST-FIRST when crossed — RSS
// plateaus instead of climbing forever.
const (
	DefaultMemoryRetention = time.Hour
	DefaultMemoryMaxBytes  = 256 << 20 // 256 MiB of accounted sample payload
)

// Memory is an in-process Writer that retains series for query (lightweight mode
// and tests), bounded by a retention window and a max-bytes wall (U-018).
// Retention ages out by ARRIVAL time (the writer is a recency buffer), so
// backfilled or clock-skewed sample timestamps are never swept early.
type Memory struct {
	mu        sync.Mutex
	entries   []memEntry // arrival order: the eviction axis
	retention time.Duration
	maxBytes  int64
	bytes     int64 // accounted size of retained samples

	evictedAge   uint64
	evictedBytes uint64
	now          func() time.Time
}

type memEntry struct {
	s         Series
	arrivalMs int64
}

// NewMemory returns an in-memory writer with the bounded defaults.
func NewMemory() *Memory { return NewMemoryWithLimits(0, 0) }

// NewMemoryWithLimits returns an in-memory writer with an explicit retention
// window and byte wall (non-positive values use the defaults).
func NewMemoryWithLimits(retention time.Duration, maxBytes int64) *Memory {
	if retention <= 0 {
		retention = DefaultMemoryRetention
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMemoryMaxBytes
	}
	return &Memory{retention: retention, maxBytes: maxBytes, now: time.Now}
}

// sampleSize is the accounted footprint of one sample (struct + strings).
func sampleSize(s Series) int64 {
	n := int64(64 + len(s.Metric))
	for k, v := range s.Labels {
		n += int64(len(k) + len(v) + 32)
	}
	return n
}

// Write retains the series, then enforces retention + the byte wall.
func (m *Memory) Write(_ context.Context, series []Series) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nowMs := m.now().UnixMilli()
	for _, s := range series {
		m.bytes += sampleSize(s)
		m.entries = append(m.entries, memEntry{s: s, arrivalMs: nowMs})
	}
	m.enforceLocked()
	return nil
}

// enforceLocked sweeps samples that ARRIVED before the retention cutoff and
// then evicts oldest-first past the byte wall.
func (m *Memory) enforceLocked() {
	cutoff := m.now().Add(-m.retention).UnixMilli()
	drop := 0
	for drop < len(m.entries) && m.entries[drop].arrivalMs < cutoff {
		m.bytes -= sampleSize(m.entries[drop].s)
		m.evictedAge++
		drop++
	}
	for drop < len(m.entries) && m.bytes > m.maxBytes {
		m.bytes -= sampleSize(m.entries[drop].s)
		m.evictedBytes++
		drop++
	}
	if drop > 0 {
		m.entries = append(m.entries[:0], m.entries[drop:]...) // keep one backing array
	}
}

// MemoryUsage reports the writer's current footprint + eviction counters
// (probectl observes probectl).
type MemoryUsage struct {
	Samples      int
	Bytes        int64
	EvictedAge   uint64 // swept by the retention window
	EvictedBytes uint64 // evicted by the byte wall (oldest-first)
}

// Usage snapshots the current accounting.
func (m *Memory) Usage() MemoryUsage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MemoryUsage{Samples: len(m.entries), Bytes: m.bytes, EvictedAge: m.evictedAge, EvictedBytes: m.evictedBytes}
}

// Close is a no-op.
func (m *Memory) Close() error { return nil }

// Query returns the retained series with the given metric name whose labels match
// all of match (a simple lightweight/test query).
func (m *Memory) Query(metric string, match map[string]string) []Series {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Series
	for _, e := range m.entries {
		s := e.s
		if s.Metric != metric {
			continue
		}
		ok := true
		for k, v := range match {
			if s.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// Len returns the total number of retained series.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Snapshot returns a copy of every retained sample. It backs the selector-query
// surfaces (Grafana datasource + federation, S40) in lightweight mode.
func (m *Memory) Snapshot() []Series {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Series, len(m.entries))
	for i, e := range m.entries {
		out[i] = e.s
	}
	return out
}

// DeleteTenant removes every retained series labeled with the tenant and
// returns how many points were removed (S-T5 verifiable deletion). The
// prometheus-mode Writer does not implement this — series deletion there is
// the documented manual step (admin delete_series API / retention).
func (m *Memory) DeleteTenant(_ context.Context, tenantID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.entries[:0]
	removed := 0
	for _, e := range m.entries {
		if e.s.Labels["tenant_id"] == tenantID {
			removed++
			m.bytes -= sampleSize(e.s)
			continue
		}
		kept = append(kept, e)
	}
	m.entries = kept
	return removed, nil
}
