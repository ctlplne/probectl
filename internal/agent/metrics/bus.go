// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agentmetrics

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
)

// ObserveBus wraps an agent's bus producer with publish RED metrics. Subscribe,
// close, flush, and subscriber-readiness behavior remain delegated unchanged.
func ObserveBus(inner bus.Bus, metrics *Runtime) bus.Bus {
	if inner == nil || metrics == nil {
		return inner
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

func (b *observedBus) WaitForSubscribers(ctx context.Context, topic string, n int) bool {
	if w, ok := b.Bus.(bus.SubscriberWaiter); ok {
		return w.WaitForSubscribers(ctx, topic, n)
	}
	return true
}
