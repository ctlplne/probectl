// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	mu        sync.RWMutex
	spans     map[string][]Span
	logs      map[string][]LogRecord
	spanIndex map[string]map[string]int
	logIndex  map[string]map[string]int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		spans:     map[string][]Span{},
		logs:      map[string][]LogRecord{},
		spanIndex: map[string]map[string]int{},
		logIndex:  map[string]map[string]int{},
	}
}

// WriteSpans appends spans under their OWN tenant ids (the consumer already
// verified/stamped them at the receiver boundary).
func (m *Memory) WriteSpans(_ context.Context, spans []Span) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initLocked()
	for _, s := range spans {
		if s.TenantID == "" {
			continue // never store an unowned row (fail closed)
		}
		key := spanDedupKey(s)
		idx := m.spanIndexFor(s.TenantID)
		if i, ok := idx[key]; ok {
			m.spans[s.TenantID][i] = s
			continue
		}
		idx[key] = len(m.spans[s.TenantID])
		m.spans[s.TenantID] = append(m.spans[s.TenantID], s)
		if over := len(m.spans[s.TenantID]) - memoryMaxPerTenant; over > 0 {
			m.spans[s.TenantID] = m.spans[s.TenantID][over:]
			m.rebuildSpanIndex(s.TenantID)
		}
	}
	return nil
}

// WriteLogs appends log records under their own tenant ids.
func (m *Memory) WriteLogs(_ context.Context, recs []LogRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initLocked()
	for _, r := range recs {
		if r.TenantID == "" {
			continue
		}
		key := logDedupID(r)
		idx := m.logIndexFor(r.TenantID)
		if i, ok := idx[key]; ok {
			m.logs[r.TenantID][i] = r
			continue
		}
		idx[key] = len(m.logs[r.TenantID])
		m.logs[r.TenantID] = append(m.logs[r.TenantID], r)
		if over := len(m.logs[r.TenantID]) - memoryMaxPerTenant; over > 0 {
			m.logs[r.TenantID] = m.logs[r.TenantID][over:]
			m.rebuildLogIndex(r.TenantID)
		}
	}
	return nil
}

// QuerySpans returns the tenant's matching spans, newest first.
func (m *Memory) QuerySpans(_ context.Context, tenant string, q SpanQuery) ([]Span, error) {
	if tenant == "" {
		return nil, ErrNoTenant // TENANT-003: fail closed on an unscoped read
	}
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
	if tenant == "" {
		return nil, ErrNoTenant // TENANT-003: fail closed on an unscoped read
	}
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

func spanDedupKey(s Span) string {
	if s.TraceID != "" && s.SpanID != "" {
		return s.TenantID + "|" + s.TraceID + "|" + s.SpanID
	}
	return s.TenantID + "|" + timeOrNow(s.Start).UTC().Format(time.RFC3339Nano) + "|" +
		s.Service + "|" + s.Name + "|" + s.Kind + "|" + s.StatusCode
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
	delete(m.spanIndex, tenant)
	delete(m.logIndex, tenant)
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

func (m *Memory) initLocked() {
	if m.spans == nil {
		m.spans = map[string][]Span{}
	}
	if m.logs == nil {
		m.logs = map[string][]LogRecord{}
	}
	if m.spanIndex == nil {
		m.spanIndex = map[string]map[string]int{}
	}
	if m.logIndex == nil {
		m.logIndex = map[string]map[string]int{}
	}
}

func (m *Memory) spanIndexFor(tenant string) map[string]int {
	idx := m.spanIndex[tenant]
	if idx == nil {
		m.rebuildSpanIndex(tenant)
		idx = m.spanIndex[tenant]
	}
	return idx
}

func (m *Memory) logIndexFor(tenant string) map[string]int {
	idx := m.logIndex[tenant]
	if idx == nil {
		m.rebuildLogIndex(tenant)
		idx = m.logIndex[tenant]
	}
	return idx
}

func (m *Memory) rebuildSpanIndex(tenant string) {
	idx := make(map[string]int, len(m.spans[tenant]))
	for i, s := range m.spans[tenant] {
		idx[spanDedupKey(s)] = i
	}
	m.spanIndex[tenant] = idx
}

func (m *Memory) rebuildLogIndex(tenant string) {
	idx := make(map[string]int, len(m.logs[tenant]))
	for i, r := range m.logs[tenant] {
		idx[logDedupID(r)] = i
	}
	m.logIndex[tenant] = idx
}
