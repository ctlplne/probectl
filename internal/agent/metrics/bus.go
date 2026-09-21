// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agentmetrics

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
)

// ObserveBus wraps an agent's bus producer with publish RED metrics. Subscribe,
// close, flush, and subscriber-readiness behavior remain delegated unchanged.
//
// DPR-140: probectl_agent_published_total counts what the TRANSPORT ACCEPTED.
// For an asynchronous producer that is intent, not delivery — Publish returns
// nil long before the broker answers — so an agent whose every record is
// rejected reported a climbing published_total and a flat errors_total. The
// eBPF agent grew its own verified-delivery counters for exactly this (DPR-071)
// and the other four bus-publishing agents had none. Any transport that can
// report undelivered records now reports them on every agent's own endpoint, so
// "delivering nothing" is a number an operator can alert on rather than a
// silence that looks like idleness.
func ObserveBus(inner bus.Bus, metrics *Runtime) bus.Bus {
	if inner == nil || metrics == nil {
		return inner
	}
	if r, ok := inner.(bus.PublishFailureReporter); ok {
		metrics.WatchGauge("probectl_agent_bus_publish_failed_total",
			"Records this agent's transport ACCEPTED that never reached the broker (failed after the client's retries). Nonzero means data was lost after probectl_agent_published_total counted it.",
			func() float64 { failed, _, _ := r.PublishFailures(); return float64(failed) })
		metrics.WatchGauge("probectl_agent_bus_publish_shed_total",
			"Records dropped at this agent's full in-flight producer buffer (broker-degraded backpressure). Also lost after published_total counted them.",
			func() float64 { _, shed, _ := r.PublishFailures(); return float64(shed) })
	}
	return &observedBus{Bus: inner, metrics: metrics}
}

type observedBus struct {
	bus.Bus
	metrics *Runtime
}

func (b *observedBus) Publish(ctx context.Context, topic string, key, value []byte) error {
	b.metrics.Collection(1)
	started := time.Now()
	err := b.Bus.Publish(ctx, topic, key, value)
	b.metrics.Publish(1, time.Since(started), err)
	return err
}

func (b *observedBus) Flush(ctx context.Context) error {
	if f, ok := b.Bus.(bus.Flusher); ok {
		return f.Flush(ctx)
	}
	return nil
}

// PublishFailures forwards the wrapped bus's asynchronous failure counters
// (bus.PublishFailureReporter) so agents can surface undelivered records
// (DPR-071); a bus without the capability reports nothing.
func (b *observedBus) PublishFailures() (failed, shed uint64, last error) {
	if r, ok := b.Bus.(bus.PublishFailureReporter); ok {
		return r.PublishFailures()
	}
	return 0, 0, nil
}

func (b *observedBus) WaitForSubscribers(ctx context.Context, topic string, n int) bool {
	if w, ok := b.Bus.(bus.SubscriberWaiter); ok {
		return w.WaitForSubscribers(ctx, topic, n)
	}
	return true
}
