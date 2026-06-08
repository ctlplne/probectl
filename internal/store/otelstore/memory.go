package otelstore

import (
	"context"
	"sort"
	"sync"
	"time"
)

// memoryMaxPerTenant bounds each tenant's in-memory signals (lightweight
// mode is not a long-retention store; ClickHouse is the production home).
const memoryMaxPerTenant = 50_000

// Memory is the in-process Store: per-tenant bounded rings, newest kept.
type Memory struct {
	mu    sync.RWMutex
	spans map[string][]Span
	logs  map[string][]LogRecord
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{spans: map[string][]Span{}, logs: map[string][]LogRecord{}}
}

// WriteSpans appends spans under their OWN tenant ids (the consumer already
// verified/stamped them at the receiver boundary).
func (m *Memory) WriteSpans(_ context.Context, spans []Span) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range spans {
		if s.TenantID == "" {
			continue // never store an unowned row (fail closed)
		}
		cur := append(m.spans[s.TenantID], s)
		if len(cur) > memoryMaxPerTenant {
			cur = cur[len(cur)-memoryMaxPerTenant:]
		}
		m.spans[s.TenantID] = cur
	}
	return nil
}

// WriteLogs appends log records under their own tenant ids.
func (m *Memory) WriteLogs(_ context.Context, recs []LogRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		if r.TenantID == "" {
			continue
		}
		cur := append(m.logs[r.TenantID], r)
		if len(cur) > memoryMaxPerTenant {
			cur = cur[len(cur)-memoryMaxPerTenant:]
		}
		m.logs[r.TenantID] = cur
	}
	return nil
}

// QuerySpans returns the tenant's matching spans, newest first.
func (m *Memory) QuerySpans(_ context.Context, tenant string, q SpanQuery) ([]Span, error) {
	limit := clampLimit(q.Limit)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Span
	for _, s := range m.spans[tenant] {
		if q.TraceID != "" && s.TraceID != q.TraceID {
			continue
		}
		if q.Service != "" && s.Service != q.Service {
			continue
		}
		if !q.Since.IsZero() && s.Start.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && s.Start.After(q.Until) {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// QueryLogs returns the tenant's matching records, newest first.
func (m *Memory) QueryLogs(_ context.Context, tenant string, q LogQuery) ([]LogRecord, error) {
	limit := clampLimit(q.Limit)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []LogRecord
	for _, r := range m.logs[tenant] {
		if q.Service != "" && r.Service != q.Service {
			continue
		}
		if q.TraceID != "" && r.TraceID != q.TraceID {
			continue
		}
		if q.MinSeverity > 0 && r.SeverityNum < q.MinSeverity {
			continue
		}
		if !q.Since.IsZero() && r.TS.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && r.TS.After(q.Until) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Len reports stored counts (tests + the scale gate).
func (m *Memory) Len(tenant string) (spans, logs int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.spans[tenant]), len(m.logs[tenant])
}

// Close is a no-op for the memory store.
func (m *Memory) Close() error { return nil }

// EraseTenant removes every signal owned by tenant (the per-tenant
// verifiable-deletion path, F-compliance / TENANT-008). It returns the count
// removed and the post-delete remaining (always 0 in memory) so the caller
// can attest verified-zero like the other stores.
func (m *Memory) EraseTenant(_ context.Context, tenant string) (deleted, remaining int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	deleted = len(m.spans[tenant]) + len(m.logs[tenant])
	delete(m.spans, tenant)
	delete(m.logs, tenant)
	return deleted, 0, nil
}

var _ Store = (*Memory)(nil)

// timeOrNow guards zero timestamps at ingest (a record with no time is
// stamped with arrival time rather than 1970).
func timeOrNow(t time.Time) time.Time {
	if t.IsZero() || t.Unix() <= 0 {
		return time.Now()
	}
	return t
}
