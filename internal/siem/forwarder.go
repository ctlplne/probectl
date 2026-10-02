// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Config tunes the forwarder's buffer + retry.
type Config struct {
	BufferSize   int           // bounded async buffer (Enqueue blocks when full)
	RetryBackoff time.Duration // initial retry backoff
	MaxBackoff   time.Duration // backoff ceiling
}

func (c Config) withDefaults() Config {
	if c.BufferSize <= 0 {
		c.BufferSize = 1024
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	return c
}

// Stats are the forwarder's delivery counters.
type Stats struct {
	Delivered int64 `json:"delivered"`
	Retried   int64 `json:"retried"`
	Buffered  int64 `json:"buffered"`
}

// Forwarder formats events and delivers them to a SIEM with retry, never dropping
// under backpressure (S32). Two entry points share one retrying delivery path:
//   - Deliver (synchronous, retry-until-success) — the audit poller uses it so a
//     durable cursor only advances past delivered events (no drops across restarts).
//   - Enqueue (async, blocks when the buffer is full) — the threat/security path
//     uses it; Run drains the buffer.
type Forwarder struct {
	fmt    Formatter
	sender Sender
	cfg    Config
	log    *slog.Logger
	ch     chan Event

	delivered atomic.Int64
	retried   atomic.Int64
}

// NewForwarder builds a forwarder over a formatter + sender.
func NewForwarder(f Formatter, s Sender, cfg Config, log *slog.Logger) *Forwarder {
	cfg = cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Forwarder{fmt: f, sender: s, cfg: cfg, log: log, ch: make(chan Event, cfg.BufferSize)}
}

// Deliver formats + sends one event, retrying with exponential backoff until it
// succeeds or ctx is canceled. It returns ctx.Err() only when canceled mid-retry,
// so a caller advancing a durable cursor never skips an undelivered event.
func (fw *Forwarder) Deliver(ctx context.Context, e Event) error {
	payload := fw.fmt.Format(e)
	backoff := fw.cfg.RetryBackoff
	for {
		err := fw.sender.Send(ctx, payload)
		if err == nil {
			fw.delivered.Add(1)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fw.retried.Add(1)
		fw.log.Warn("siem delivery failed; retrying", "format", fw.fmt.Name(), "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < fw.cfg.MaxBackoff {
			if backoff *= 2; backoff > fw.cfg.MaxBackoff {
				backoff = fw.cfg.MaxBackoff
			}
		}
	}
}

// DeliverBatch formats a whole batch into ONE payload and sends it in a single
// POST, retrying with exponential backoff until it succeeds or ctx is canceled.
// It is the audit poller's export path (AUD-16): one HTTPS request per page of
// events instead of one per event, so throughput no longer collapses under SIEM
// latency. The batch is a SINGLE tenant's events (per-tenant draining), so the
// payload never mixes tenants (docs/guardrails.md G7-N). Like Deliver, it
// returns ctx.Err() only when canceled mid-retry, so a caller that advances its
// durable cursor only on a nil return never skips an undelivered batch
// (at-least-once: a batch re-sent after a mid-flight failure is a duplicate the
// SIEM dedups on audit.seq, never a drop).
func (fw *Forwarder) DeliverBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	payload := fw.fmt.FormatBatch(events)
	backoff := fw.cfg.RetryBackoff
	for {
		err := fw.sender.Send(ctx, payload)
		if err == nil {
			fw.delivered.Add(int64(len(events)))
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fw.retried.Add(1)
		fw.log.Warn("siem batch delivery failed; retrying", "format", fw.fmt.Name(), "events", len(events), "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < fw.cfg.MaxBackoff {
			if backoff *= 2; backoff > fw.cfg.MaxBackoff {
				backoff = fw.cfg.MaxBackoff
			}
		}
	}
}

// Enqueue buffers an event for async delivery, BLOCKING when the buffer is full
// (backpressure — events are never dropped). Returns ctx.Err() if canceled while
// blocked.
func (fw *Forwarder) Enqueue(ctx context.Context, e Event) error {
	select {
	case fw.ch <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run drains the async buffer, delivering each event (with retry) until ctx is
// canceled. The threat/security path enqueues; the audit path calls Deliver.
func (fw *Forwarder) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-fw.ch:
			_ = fw.Deliver(ctx, e)
		}
	}
}

// Stats returns the current delivery counters.
func (fw *Forwarder) Stats() Stats {
	return Stats{Delivered: fw.delivered.Load(), Retried: fw.retried.Load(), Buffered: int64(len(fw.ch))}
}
