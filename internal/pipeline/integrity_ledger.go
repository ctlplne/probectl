// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"sync/atomic"

	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// IntegrityStats is the per-signal receipt ledger exposed by ingest consumers.
// Process metrics carry only aggregate counts by plane/signal; tenant detail
// stays in structured logs and tenant-scoped APIs.
type IntegrityStats struct {
	Received           uint64
	Stored             uint64
	Malformed          uint64
	TenantRejected     uint64
	FairnessShed       uint64
	CardinalityDropped uint64
	LabelTruncated     uint64
	Unsupported        uint64
	DeadLettered       uint64
	Dropped            uint64
}

type integrityLedger struct {
	signal string

	received           atomic.Uint64
	stored             atomic.Uint64
	malformed          atomic.Uint64
	tenantRejected     atomic.Uint64
	fairnessShed       atomic.Uint64
	cardinalityDropped atomic.Uint64
	labelTruncated     atomic.Uint64
	unsupported        atomic.Uint64
	deadLettered       atomic.Uint64
	dropped            atomic.Uint64

	metrics integrityCounters
}

type integrityCounters struct {
	received           *metrics.Counter
	stored             *metrics.Counter
	malformed          *metrics.Counter
	tenantRejected     *metrics.Counter
	fairnessShed       *metrics.Counter
	cardinalityDropped *metrics.Counter
	labelTruncated     *metrics.Counter
	unsupported        *metrics.Counter
	deadLettered       *metrics.Counter
	dropped            *metrics.Counter
}

func newIntegrityLedger(signal string) *integrityLedger {
	return &integrityLedger{signal: signal}
}

func (l *integrityLedger) withMetrics(reg *metrics.Registry) {
	if l == nil || reg == nil {
		return
	}
	prefix := "probectl_pipeline_" + l.signal + "_"
	l.metrics.received = reg.Counter(prefix+"received_total", "Ingest payloads received by the "+l.signal+" pipeline.")
	l.metrics.stored = reg.Counter(prefix+"stored_total", "Ingest payloads stored by the "+l.signal+" pipeline.")
	l.metrics.malformed = reg.Counter(prefix+"malformed_total", "Malformed ingest payloads dropped by the "+l.signal+" pipeline.")
	l.metrics.tenantRejected = reg.Counter(prefix+"tenant_rejected_total", "Tenant-verification rejects in the "+l.signal+" pipeline.")
	l.metrics.fairnessShed = reg.Counter(prefix+"fairness_shed_total", "Payloads shed by fairness bounds in the "+l.signal+" pipeline.")
	l.metrics.cardinalityDropped = reg.Counter(prefix+"cardinality_dropped_total", "Series or records dropped by cardinality caps in the "+l.signal+" pipeline.")
	l.metrics.labelTruncated = reg.Counter(prefix+"label_truncated_total", "Label values normalized by cardinality bounds in the "+l.signal+" pipeline.")
	l.metrics.unsupported = reg.Counter(prefix+"unsupported_total", "Unsupported telemetry units skipped by the "+l.signal+" pipeline.")
	l.metrics.deadLettered = reg.Counter(prefix+"dead_lettered_total", "Payloads dead-lettered by the "+l.signal+" pipeline.")
	l.metrics.dropped = reg.Counter(prefix+"dropped_total", "Payloads lost after store and dead-letter publish both failed in the "+l.signal+" pipeline.")
}

func (l *integrityLedger) addReceived(n uint64) {
	if l != nil {
		l.add(&l.received, l.metrics.received, n)
	}
}

func (l *integrityLedger) addStored(n uint64) {
	if l != nil {
		l.add(&l.stored, l.metrics.stored, n)
	}
}

func (l *integrityLedger) addMalformed(n uint64) {
	if l != nil {
		l.add(&l.malformed, l.metrics.malformed, n)
	}
}

func (l *integrityLedger) addTenantRejected(n uint64) {
	if l != nil {
		l.add(&l.tenantRejected, l.metrics.tenantRejected, n)
	}
}

func (l *integrityLedger) addFairnessShed(n uint64) {
	if l != nil {
		l.add(&l.fairnessShed, l.metrics.fairnessShed, n)
	}
}

func (l *integrityLedger) addCardinalityDropped(n uint64) {
	if l != nil {
		l.add(&l.cardinalityDropped, l.metrics.cardinalityDropped, n)
	}
}

func (l *integrityLedger) addLabelTruncated(n uint64) {
	if l != nil {
		l.add(&l.labelTruncated, l.metrics.labelTruncated, n)
	}
}

func (l *integrityLedger) addUnsupported(n uint64) {
	if l != nil {
		l.add(&l.unsupported, l.metrics.unsupported, n)
	}
}

func (l *integrityLedger) addDeadLettered(n uint64) {
	if l != nil {
		l.add(&l.deadLettered, l.metrics.deadLettered, n)
	}
}

func (l *integrityLedger) addDropped(n uint64) {
	if l != nil {
		l.add(&l.dropped, l.metrics.dropped, n)
	}
}

func (l *integrityLedger) add(counter *atomic.Uint64, metric *metrics.Counter, n uint64) {
	if l == nil || n == 0 {
		return
	}
	counter.Add(n)
	if metric != nil {
		metric.Add(n)
	}
}

func (l *integrityLedger) stats() IntegrityStats {
	if l == nil {
		return IntegrityStats{}
	}
	return IntegrityStats{
		Received:           l.received.Load(),
		Stored:             l.stored.Load(),
		Malformed:          l.malformed.Load(),
		TenantRejected:     l.tenantRejected.Load(),
		FairnessShed:       l.fairnessShed.Load(),
		CardinalityDropped: l.cardinalityDropped.Load(),
		LabelTruncated:     l.labelTruncated.Load(),
		Unsupported:        l.unsupported.Load(),
		DeadLettered:       l.deadLettered.Load(),
		Dropped:            l.dropped.Load(),
	}
}
