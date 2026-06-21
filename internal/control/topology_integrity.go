// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"sync/atomic"

	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// TopologyPlaneIntegrityStats is the aggregate receipt/loss ledger for one
// topology-derived plane. It is process-level self-observability only: no
// tenant labels or tenant data ever appear in /metrics.
type TopologyPlaneIntegrityStats struct {
	Received      uint64
	Stored        uint64
	Malformed     uint64
	Rejected      uint64
	Unscoped      uint64
	PersistFailed uint64
}

// TopologyIntegrityStats reports topology consumer health by source plane.
type TopologyIntegrityStats struct {
	EBPF   TopologyPlaneIntegrityStats
	BGP    TopologyPlaneIntegrityStats
	Device TopologyPlaneIntegrityStats
}

type topologyIntegrityLedger struct {
	ebpf   topologyPlaneLedger
	bgp    topologyPlaneLedger
	device topologyPlaneLedger
}

type topologyPlaneLedger struct {
	plane string

	received      atomic.Uint64
	stored        atomic.Uint64
	malformed     atomic.Uint64
	rejected      atomic.Uint64
	unscoped      atomic.Uint64
	persistFailed atomic.Uint64

	metrics topologyPlaneCounters
}

type topologyPlaneCounters struct {
	received      *metrics.Counter
	stored        *metrics.Counter
	malformed     *metrics.Counter
	rejected      *metrics.Counter
	unscoped      *metrics.Counter
	persistFailed *metrics.Counter
}

func newTopologyIntegrityLedger() *topologyIntegrityLedger {
	return &topologyIntegrityLedger{
		ebpf:   topologyPlaneLedger{plane: "ebpf"},
		bgp:    topologyPlaneLedger{plane: "bgp"},
		device: topologyPlaneLedger{plane: "device"},
	}
}

// WithMetrics exports topology integrity counters at /metrics.
func (tc *TopologyConsumer) WithMetrics(reg *metrics.Registry) *TopologyConsumer {
	if tc != nil && tc.ledger != nil {
		tc.ledger.withMetrics(reg)
	}
	return tc
}

// IntegrityStats returns topology receipt/loss counters for tests and
// diagnostics. Unknown/nil consumers report zeros rather than panicking.
func (tc *TopologyConsumer) IntegrityStats() TopologyIntegrityStats {
	if tc == nil || tc.ledger == nil {
		return TopologyIntegrityStats{}
	}
	return tc.ledger.stats()
}

func (l *topologyIntegrityLedger) withMetrics(reg *metrics.Registry) {
	if l == nil || reg == nil {
		return
	}
	for _, p := range []*topologyPlaneLedger{&l.ebpf, &l.bgp, &l.device} {
		p.withMetrics(reg)
	}
}

func (p *topologyPlaneLedger) withMetrics(reg *metrics.Registry) {
	if p == nil || reg == nil {
		return
	}
	prefix := "probectl_topology_" + p.plane + "_"
	p.metrics.received = reg.Counter(prefix+"received_total", "Topology "+p.plane+" payloads received.")
	p.metrics.stored = reg.Counter(prefix+"stored_total", "Topology "+p.plane+" records folded into the graph.")
	p.metrics.malformed = reg.Counter(prefix+"malformed_total", "Malformed topology "+p.plane+" payloads or records dropped.")
	p.metrics.rejected = reg.Counter(prefix+"rejected_total", "Topology "+p.plane+" payloads rejected by tenant verification.")
	p.metrics.unscoped = reg.Counter(prefix+"unscoped_total", "Topology "+p.plane+" records dropped because tenant scope was missing.")
	p.metrics.persistFailed = reg.Counter(prefix+"persist_failed_total", "Topology "+p.plane+" records whose durable sidecar persistence failed.")
}

func (l *topologyIntegrityLedger) addReceived(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.received, p.metrics.received, n)
}

func (l *topologyIntegrityLedger) addStored(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.stored, p.metrics.stored, n)
}

func (l *topologyIntegrityLedger) addMalformed(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.malformed, p.metrics.malformed, n)
}

func (l *topologyIntegrityLedger) addRejected(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.rejected, p.metrics.rejected, n)
}

func (l *topologyIntegrityLedger) addUnscoped(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.unscoped, p.metrics.unscoped, n)
}

func (l *topologyIntegrityLedger) addPersistFailed(plane string, n uint64) {
	p := l.plane(plane)
	if p == nil {
		return
	}
	p.add(&p.persistFailed, p.metrics.persistFailed, n)
}

func (l *topologyIntegrityLedger) plane(plane string) *topologyPlaneLedger {
	if l == nil {
		return nil
	}
	switch plane {
	case "bgp":
		return &l.bgp
	case "device":
		return &l.device
	default:
		return &l.ebpf
	}
}

func (p *topologyPlaneLedger) add(counter *atomic.Uint64, metric *metrics.Counter, n uint64) {
	if p == nil || counter == nil || n == 0 {
		return
	}
	counter.Add(n)
	if metric != nil {
		metric.Add(n)
	}
}

func (l *topologyIntegrityLedger) stats() TopologyIntegrityStats {
	if l == nil {
		return TopologyIntegrityStats{}
	}
	return TopologyIntegrityStats{
		EBPF:   l.ebpf.stats(),
		BGP:    l.bgp.stats(),
		Device: l.device.stats(),
	}
}

func (p *topologyPlaneLedger) stats() TopologyPlaneIntegrityStats {
	if p == nil {
		return TopologyPlaneIntegrityStats{}
	}
	return TopologyPlaneIntegrityStats{
		Received:      p.received.Load(),
		Stored:        p.stored.Load(),
		Malformed:     p.malformed.Load(),
		Rejected:      p.rejected.Load(),
		Unscoped:      p.unscoped.Load(),
		PersistFailed: p.persistFailed.Load(),
	}
}
