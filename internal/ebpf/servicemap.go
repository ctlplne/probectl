// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// edgeKey identifies a directed service edge. The tenant is part of the key so
// edges from different tenants can NEVER merge — the agent is single-tenant in
// production, but keying on tenant keeps a replayed multi-tenant fixture
// correctly separated (defense-in-depth, CLAUDE.md §7 guardrail 1).
type edgeKey struct {
	tenant      string
	source      string
	destination string
	destPort    uint32
	transport   string
}

// ServiceMap aggregates observed Flows into directed ServiceEdges. It is safe
// for concurrent use.
type ServiceMap struct {
	mu    sync.Mutex
	edges map[edgeKey]*ServiceEdge

	// Bounds (SCALE-003). A privileged eBPF agent on a busy host can observe an
	// unbounded number of distinct edges (scanners, ephemeral clients), and the
	// map both grew without limit AND re-emitted the whole snapshot every tick.
	// maxEdges caps the live set (least-recently-seen evicted); idleTTL drops
	// edges not seen within the window on Prune. Zero = unbounded (the previous
	// behavior; tests/lightweight keep it).
	maxEdges int
	idleTTL  time.Duration
	evicted  atomic.Uint64
}

// NewServiceMap returns an empty service map.
func NewServiceMap() *ServiceMap {
	return &ServiceMap{edges: make(map[edgeKey]*ServiceEdge)}
}

// SetBounds configures the max live-edge cap and idle-TTL (SCALE-003). A
// non-positive value leaves that bound unset.
func (m *ServiceMap) SetBounds(maxEdges int, idleTTL time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxEdges, m.idleTTL = maxEdges, idleTTL
}

// Evicted reports how many edges have been dropped by the cap or idle-TTL
// (SCALE-003 observability — a runaway map is visible, not silent).
func (m *ServiceMap) Evicted() uint64 { return m.evicted.Load() }

// evictOldestLocked drops the least-recently-seen edge (caller holds m.mu).
func (m *ServiceMap) evictOldestLocked() {
	var oldestK edgeKey
	var oldest time.Time
	first := true
	for k, e := range m.edges {
		if first || e.LastSeen.Before(oldest) {
			oldestK, oldest, first = k, e.LastSeen, false
		}
	}
	if !first {
		delete(m.edges, oldestK)
		m.evicted.Add(1)
	}
}

// Prune drops edges not observed within idleTTL of now (SCALE-003). No-op when
// idleTTL is unset. Returns the number pruned.
func (m *ServiceMap) Prune(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idleTTL <= 0 {
		return 0
	}
	cutoff := now.Add(-m.idleTTL)
	n := 0
	for k, e := range m.edges {
		if e.LastSeen.Before(cutoff) {
			delete(m.edges, k)
			n++
		}
	}
	m.evicted.Add(uint64(n))
	return n
}

// Observe folds one flow into the map.
func (m *ServiceMap) Observe(f Flow) {
	k := edgeKey{
		tenant:      f.TenantID,
		source:      f.Source.ID(),
		destination: f.Destination.ID(),
		destPort:    f.Destination.Port,
		transport:   f.Transport,
	}
	ts := f.Observed
	if ts.IsZero() {
		ts = time.Now()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.edges[k]
	if e == nil {
		if m.maxEdges > 0 && len(m.edges) >= m.maxEdges {
			m.evictOldestLocked() // SCALE-003: bound the live edge set
		}
		e = &ServiceEdge{
			TenantID:    f.TenantID,
			Source:      k.source,
			Destination: k.destination,
			DestPort:    k.destPort,
			Transport:   k.transport,
			FirstSeen:   ts,
			LastSeen:    ts,
		}
		m.edges[k] = e
	}
	if f.State != StateClose || e.Connections == 0 {
		e.Connections++
	}
	e.Bytes += f.Bytes
	e.Packets += f.Packets
	if ts.Before(e.FirstSeen) {
		e.FirstSeen = ts
	}
	if ts.After(e.LastSeen) {
		e.LastSeen = ts
	}
}

// ObserveL7 folds one parsed L7 call onto the edge it belongs to (the call's
// client→server orientation), creating the edge if no flow has been seen for it.
func (m *ServiceMap) ObserveL7(rec L7Record) {
	k := edgeKey{
		tenant:      rec.TenantID,
		source:      rec.Source.ID(),
		destination: rec.Destination.ID(),
		destPort:    rec.Destination.Port,
		transport:   rec.Transport,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.edges[k]
	if e == nil {
		if m.maxEdges > 0 && len(m.edges) >= m.maxEdges {
			m.evictOldestLocked() // SCALE-003: bound the live edge set
		}
		e = &ServiceEdge{
			TenantID:    rec.TenantID,
			Source:      k.source,
			Destination: k.destination,
			DestPort:    k.destPort,
			Transport:   k.transport,
			FirstSeen:   rec.Call.Start,
			LastSeen:    rec.Call.Start,
		}
		m.edges[k] = e
	}
	e.L7Protocol = rec.Call.Protocol
	e.L7Calls++
	if rec.Call.Error {
		e.L7Errors++
	}
	e.L7LatencySum += rec.Call.Latency
	if rec.Call.Latency > e.L7LatencyMax {
		e.L7LatencyMax = rec.Call.Latency
	}
	if end := rec.Call.Start.Add(rec.Call.Latency); end.After(e.LastSeen) {
		e.LastSeen = end
	}
}

// Snapshot returns a stable, sorted copy of the current edges.
func (m *ServiceMap) Snapshot() []ServiceEdge {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ServiceEdge, 0, len(m.edges))
	for _, e := range m.edges {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		switch {
		case out[i].TenantID != out[j].TenantID:
			return out[i].TenantID < out[j].TenantID
		case out[i].Source != out[j].Source:
			return out[i].Source < out[j].Source
		case out[i].Destination != out[j].Destination:
			return out[i].Destination < out[j].Destination
		default:
			return out[i].DestPort < out[j].DestPort
		}
	})
	return out
}

// Len returns the number of distinct edges.
func (m *ServiceMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.edges)
}
