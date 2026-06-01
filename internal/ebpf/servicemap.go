package ebpf

import (
	"sort"
	"sync"
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
}

// NewServiceMap returns an empty service map.
func NewServiceMap() *ServiceMap {
	return &ServiceMap{edges: make(map[edgeKey]*ServiceEdge)}
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
	e.Connections++
	e.Bytes += f.Bytes
	e.Packets += f.Packets
	if ts.Before(e.FirstSeen) {
		e.FirstSeen = ts
	}
	if ts.After(e.LastSeen) {
		e.LastSeen = ts
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
