package ebpf

import (
	"sync"
	"sync/atomic"
)

// Stats are the cumulative counters the agent exposes so probectl observes probectl:
// Dropped (ring-buffer backpressure) is surfaced, never silent — a dropped flow
// is a correctness gap in an observability tool (CLAUDE.md / S20 watch-out).
type Stats struct {
	Observed   uint64
	L7Observed uint64
	Dropped    uint64
	Edges      uint64
	// L7AttachFailures counts TLS-uprobe attach failures (U-015): an
	// encrypted-traffic visibility gap is surfaced, never silent.
	L7AttachFailures uint64
	// FilteredNonIPv4 counts flows dropped IN-KERNEL because they are not
	// IPv4 (l4flow captures IPv4 only today; U-073). The blind spot is
	// measurable, not silent — an IPv6-heavy host shows a rising count.
	FilteredNonIPv4 uint64
}

// Aggregator turns a stream of observed Flows into (a) a live ServiceMap and
// (b) periodic batches for emission, while accounting for source drops.
type Aggregator struct {
	mu        sync.Mutex
	pending   []Flow
	l7pending []L7Record
	smap      *ServiceMap

	observed        atomic.Uint64
	l7observed      atomic.Uint64
	dropped         atomic.Uint64
	l7attachFailed  atomic.Uint64
	filteredNonIPv4 atomic.Uint64
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

// RecordFilteredNonIPv4 adds n to the in-kernel non-IPv4 filter counter
// (U-073) so the IPv4-only capture limitation is measurable.
func (a *Aggregator) RecordFilteredNonIPv4(n uint64) { a.filteredNonIPv4.Add(n) }

// RecordL7AttachFailure counts a failed TLS-uprobe attach (U-015) so the
// L7-visibility gap shows up in the agent's own telemetry.
func (a *Aggregator) RecordL7AttachFailure() { a.l7attachFailed.Add(1) }

// ObserveL7 records one parsed L7 call: it rolls the call onto its service edge
// and queues it for the next emission batch.
func (a *Aggregator) ObserveL7(rec L7Record) {
	a.smap.ObserveL7(rec)
	a.mu.Lock()
	a.l7pending = append(a.l7pending, rec)
	a.mu.Unlock()
	a.l7observed.Add(1)
}

// DrainL7 returns and clears the pending L7 records.
func (a *Aggregator) DrainL7() []L7Record {
	a.mu.Lock()
	l7 := a.l7pending
	a.l7pending = nil
	a.mu.Unlock()
	return l7
}

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
		Observed:         a.observed.Load(),
		L7Observed:       a.l7observed.Load(),
		Dropped:          a.dropped.Load(),
		Edges:            uint64(a.smap.Len()),
		L7AttachFailures: a.l7attachFailed.Load(),
		FilteredNonIPv4:  a.filteredNonIPv4.Load(),
	}
}
