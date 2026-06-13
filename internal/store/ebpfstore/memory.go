// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is the in-process eBPF-aggregate store (lightweight mode + tests). It
// is tenant-partitioned and dedups on the edge's identity (CORRECT-002
// discipline) by summing a re-observed identical window in place rather than
// appending — the in-RAM analogue of the ClickHouse ReplacingMergeTree.
type Memory struct {
	mu      sync.RWMutex
	tenants map[string]map[string]*Edge // tenant -> edge key -> aggregate
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{tenants: map[string]map[string]*Edge{}} }

func edgeKey(e Edge) string {
	return e.WindowStart.UTC().Format(time.RFC3339) + "|" + e.AgentID + "|" +
		e.SrcWorkload + "|" + e.DstWorkload + "|" + e.L7Protocol + "|" +
		string(rune(e.DstPort))
}

// Insert folds each edge into the tenant's map (tenant-scoped; rows without a
// tenant are dropped fail-closed).
func (m *Memory) Insert(_ context.Context, edges []Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range edges {
		if e.TenantID == "" {
			continue
		}
		tm := m.tenants[e.TenantID]
		if tm == nil {
			tm = map[string]*Edge{}
			m.tenants[e.TenantID] = tm
		}
		k := edgeKey(e)
		if cur, ok := tm[k]; ok {
			// Re-observation of the same window/edge: replace (ReplacingMergeTree
			// semantics — last write wins for an identical key).
			cp := e
			cur.Bytes, cur.Packets, cur.Connections = cp.Bytes, cp.Packets, cp.Connections
			continue
		}
		cp := e
		tm[k] = &cp
	}
	return nil
}

// TopEdges returns a tenant's heaviest edges in the window, bytes-descending.
func (m *Memory) TopEdges(_ context.Context, tenantID string, q EdgeQuery) ([]Edge, error) {
	if tenantID == "" {
		return nil, ErrNoTenant
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Edge
	for _, e := range m.tenants[tenantID] {
		if !q.Since.IsZero() && e.WindowStart.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.WindowStart.After(q.Until) {
			continue
		}
		if q.SrcLike != "" && e.SrcWorkload != q.SrcLike {
			continue
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if lim := clampLimit(q.Limit); len(out) > lim {
		out = out[:lim]
	}
	return out, nil
}

// DeleteTenant drops every aggregate of one tenant (verifiable erasure).
func (m *Memory) DeleteTenant(_ context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tenants, tenantID)
	return 0, nil
}

// Close is a no-op for the in-memory store.
func (m *Memory) Close() error { return nil }
