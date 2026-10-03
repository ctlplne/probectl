// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// ING-19: the in-memory bus is a LIVE pub/sub with no backlog. A standalone
// collector process has no in-process consumer, so every Publish finds no
// subscriber and the batch is discarded. That loss must be COUNTED, never
// reported as a silent Publish success.
func TestMemoryPublishWithoutSubscriberCountsLoss(t *testing.T) {
	b := NewMemory()
	defer func() { _ = b.Close() }()

	// A memory bus satisfies the NoSubscriberReporter capability, so the agent
	// metrics seam can surface the loss.
	if _, ok := Bus(b).(NoSubscriberReporter); !ok {
		t.Fatalf("*Memory must implement NoSubscriberReporter so the loss is surfaced")
	}

	ctx := context.Background()
	const n = 3
	for i := 0; i < n; i++ {
		if err := b.Publish(ctx, NetworkResultsTopic, []byte("t-acme"), []byte("payload")); err != nil {
			t.Fatalf("publish %d: unexpected error: %v", i, err)
		}
	}
	if got := b.NoSubscriberDrops(); got != n {
		t.Fatalf("no-subscriber publishes must be counted as loss: got %d, want %d", got, n)
	}

	// With a subscriber present the record is delivered, not dropped, so the loss
	// counter must NOT advance — the count is specific to the no-consumer case.
	received := make(chan struct{}, 1)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_ = b.Subscribe(subCtx, NetworkResultsTopic, "g", func(context.Context, Message) error {
			received <- struct{}{}
			return nil
		})
	}()
	waitForSubscriberCount(t, b, NetworkResultsTopic, 1)

	before := b.NoSubscriberDrops()
	if err := b.Publish(ctx, NetworkResultsTopic, []byte("t-acme"), []byte("payload")); err != nil {
		t.Fatalf("publish with subscriber: unexpected error: %v", err)
	}
	<-received
	if got := b.NoSubscriberDrops(); got != before {
		t.Fatalf("a delivered record must not count as a no-subscriber drop: got %d, want %d", got, before)
	}
}

// ING-19: a collector started on the volatile in-process memory bus must warn
// LOUDLY at startup, so a standalone misconfiguration is obvious at boot rather
// than a silent, total telemetry loss.
func TestWarnIfInProcessWarnsOnMemoryMode(t *testing.T) {
	warns := func(t *testing.T, mode string) string {
		t.Helper()
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		WarnIfInProcess(log, "probectl-test", mode)
		return buf.String()
	}

	for _, mode := range []string{"", "memory"} {
		out := warns(t, mode)
		if !strings.Contains(out, "level=WARN") {
			t.Fatalf("mode %q must emit a WARN; got %q", mode, out)
		}
		for _, want := range []string{"finding=ING-19", "bus_mode=memory", "component=probectl-test"} {
			if !strings.Contains(out, want) {
				t.Fatalf("mode %q WARN must contain %q; got %q", mode, want, out)
			}
		}
	}

	for _, mode := range []string{"nats", "kafka"} {
		if out := warns(t, mode); out != "" {
			t.Fatalf("durable mode %q must not warn; got %q", mode, out)
		}
	}

	// A nil logger must never panic (the helper is called before every collector
	// has a logger guaranteed non-nil).
	WarnIfInProcess(nil, "probectl-test", "memory")
}
