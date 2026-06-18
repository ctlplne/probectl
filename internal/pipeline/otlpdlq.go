// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// otlpDLQ is the shared store-write resilience for the three OTLP consumers —
// the SAME contract as the results/device plane (consumer.go): a bounded
// jittered retry, then dead-letter the ORIGINAL message bytes to a per-signal
// DLQ topic and COUNT it, so an externally-ingested OTLP write failure is
// never a silent best-effort drop (SCALE-003 / ARCH-002). The counters
// optionally surface at /metrics (probectl_otlp_<signal>_{dead_lettered,
// dropped}_total) when a registry is wired.
type otlpDLQ struct {
	bus      bus.Bus
	dlqTopic string
	signal   string // "metrics" | "traces" | "logs" (logs + counter names)

	maxRetries int
	retryBase  time.Duration
	sleep      func(context.Context, time.Duration) // injectable for tests
	log        *slog.Logger

	retried      atomic.Uint64
	deadLettered atomic.Uint64
	dropped      atomic.Uint64
	dlMetric     *metrics.Counter // optional /metrics surface
	dropMetric   *metrics.Counter
	ledger       *integrityLedger
}

func newOTLPDLQ(b bus.Bus, dlqTopic, signal string, log *slog.Logger, ledger *integrityLedger) *otlpDLQ {
	if log == nil {
		log = slog.Default()
	}
	d := &otlpDLQ{bus: b, dlqTopic: dlqTopic, signal: signal, maxRetries: 3, retryBase: 50 * time.Millisecond, log: log, ledger: ledger}
	d.sleep = d.defaultSleep
	return d
}

func (d *otlpDLQ) defaultSleep(ctx context.Context, dur time.Duration) {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// withMetrics registers the dead-letter/drop counters in reg so they appear at
// /metrics. No-op when reg is nil (the counters are still tracked as atomics).
func (d *otlpDLQ) withMetrics(reg *metrics.Registry) {
	if reg == nil {
		return
	}
	d.dlMetric = reg.Counter("probectl_otlp_"+d.signal+"_dead_lettered_total",
		"OTLP "+d.signal+" messages dead-lettered after store-write retries were exhausted.")
	d.dropMetric = reg.Counter("probectl_otlp_"+d.signal+"_dropped_total",
		"OTLP "+d.signal+" messages lost: store write AND dead-letter publish both failed.")
}

// process attempts write up to 1+maxRetries times with jittered exponential
// backoff; on exhaustion it dead-letters msg (original bytes) and counts it. It
// reports whether the write SUCCEEDED (so the caller counts stored records). A
// dead-lettered or dropped message is "handled" and returns nil; a
// cancellation/deadline write result is an unknown outcome and returns an error
// so the bus leaves the offset uncommitted instead of DLQing a possible double.
func (d *otlpDLQ) process(ctx context.Context, msg bus.Message, write func(context.Context) error) (stored bool, err error) {
	for attempt := 0; ; attempt++ {
		if err = write(ctx); err == nil {
			return true, nil
		}
		if attempt >= d.maxRetries || ctx.Err() != nil {
			break
		}
		d.retried.Add(1)
		backoff := d.retryBase << attempt
		d.sleep(ctx, backoff+time.Duration(rand.Int64N(int64(backoff)/2+1)))
	}
	if unknownWriteOutcome(ctx, err) {
		return false, err
	}
	d.deadLetter(ctx, msg, err)
	return false, nil
}

// deadLetter routes the ORIGINAL message bytes to the per-signal DLQ topic
// (tenant-keyed, replayable) and accounts the outcome. A DLQ publish failure is
// the only true loss — counted and logged at ERROR.
func (d *otlpDLQ) deadLetter(ctx context.Context, msg bus.Message, writeErr error) {
	tenant := string(tenantFromKey(msg.Key))
	if perr := d.bus.Publish(ctx, d.dlqTopic, msg.Key, msg.Value); perr != nil {
		d.dropped.Add(1)
		d.ledger.addDropped(1)
		if d.dropMetric != nil {
			d.dropMetric.Inc()
		}
		d.log.Error("OTLP "+d.signal+" LOST: store write exhausted retries and dead-letter publish failed",
			"tenant_id", tenant, "write_error", errStr(writeErr), "dlq_error", perr.Error(),
			"dropped_total", d.dropped.Load())
		return
	}
	d.deadLettered.Add(1)
	d.ledger.addDeadLettered(1)
	if d.dlMetric != nil {
		d.dlMetric.Inc()
	}
	d.log.Error("OTLP "+d.signal+" store write exhausted retries — dead-lettered (replayable)",
		"tenant_id", tenant, "topic", d.dlqTopic, "error", errStr(writeErr),
		"dead_lettered_total", d.deadLettered.Load())
}

// DLQStats reports the cumulative retry/DLQ counters (test + observability hook).
type DLQStats struct {
	Retried      uint64
	DeadLettered uint64
	Dropped      uint64
}

func (d *otlpDLQ) stats() DLQStats {
	return DLQStats{Retried: d.retried.Load(), DeadLettered: d.deadLettered.Load(), Dropped: d.dropped.Load()}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
