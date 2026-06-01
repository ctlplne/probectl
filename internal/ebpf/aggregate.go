package ebpf

import (
	"sync"
	"sync/atomic"
)

// Stats are the cumulative counters the agent exposes so netctl observes netctl:
// Dropped (ring-buffer backpressure) is surfaced, never silent — a dropped flow
// is a correctness gap in an observability tool (CLAUDE.md / S20 watch-out).
type Stats struct {
	Observed uint64
	Dropped  uint64
	Edges    uint64
}

// Aggregator turns a stream of observed Flows into (a) a live ServiceMap and
// (b) periodic batches for emission, while accounting for source drops.
type Aggregator struct {
	mu      sync.Mutex
	pending []Flow
	smap    *ServiceMap

	observed atomic.Uint64
	dropped  atomic.Uint64
}

// NewAggregator returns an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{smap: NewServiceMap()}
}

// Observe records one flow: it updates the service map and queues the flow for
// the next emission batch.
func (a *Aggregator) Observe(f Flow) {
	a.smap.Observe(f)
	a.mu.Lock()
	a.pending = append(a.pending, f)
	a.mu.Unlock()
	a.observed.Add(1)
}

// RecordDrops adds n to the dropped counter (ring-buffer backpressure).
func (a *Aggregator) RecordDrops(n uint64) { a.dropped.Add(n) }

// Drain returns and clears the pending flows, plus a snapshot of the current
// (cumulative) service map, for emission.
func (a *Aggregator) Drain() ([]Flow, []ServiceEdge) {
	a.mu.Lock()
	flows := a.pending
	a.pending = nil
	a.mu.Unlock()
	return flows, a.smap.Snapshot()
}

// ServiceMap exposes the live map (e.g. for a snapshot API).
func (a *Aggregator) ServiceMap() *ServiceMap { return a.smap }

// Stats reports the cumulative counters.
func (a *Aggregator) Stats() Stats {
	return Stats{
		Observed: a.observed.Load(),
		Dropped:  a.dropped.Load(),
		Edges:    uint64(a.smap.Len()),
	}
}
