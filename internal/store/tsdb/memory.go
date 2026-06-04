package tsdb

import (
	"context"
	"sync"
)

// Memory is an in-process Writer that retains series for query (lightweight mode
// and tests).
type Memory struct {
	mu     sync.Mutex
	series []Series
}

// NewMemory returns an in-memory writer.
func NewMemory() *Memory { return &Memory{} }

// Write retains the series.
func (m *Memory) Write(_ context.Context, series []Series) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.series = append(m.series, series...)
	return nil
}

// Close is a no-op.
func (m *Memory) Close() error { return nil }

// Query returns the retained series with the given metric name whose labels match
// all of match (a simple lightweight/test query).
func (m *Memory) Query(metric string, match map[string]string) []Series {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Series
	for _, s := range m.series {
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
	return len(m.series)
}

// Snapshot returns a copy of every retained sample. It backs the selector-query
// surfaces (Grafana datasource + federation, S40) in lightweight mode.
func (m *Memory) Snapshot() []Series {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Series, len(m.series))
	copy(out, m.series)
	return out
}
