// SPDX-License-Identifier: LicenseRef-probectl-TBD

package bus

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// CORRECT-007: the in-memory bus used to discard a handler error
// (`_ = handler(...)`) — unlike Kafka, which leaves the offset uncommitted and
// redelivers. That made the lightweight (<5-agent) mode silently lose a record
// whose handler failed. Now a handler error is COUNTED and the record is
// REDELIVERED up to a bound, then counted as lost — never swallowed.
func TestMemoryRedeliversOnHandlerError(t *testing.T) {
	t.Run("transient_error_is_redelivered_then_succeeds", func(t *testing.T) {
		m := NewMemory()
		defer m.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var calls atomic.Int32
		done := make(chan struct{})
		go func() {
			_ = m.Subscribe(ctx, "t", "g", func(context.Context, Message) error {
				n := calls.Add(1)
				if n < 3 { // fail the first two deliveries, then succeed
					return errors.New("transient")
				}
				close(done)
				return nil
			})
		}()
		awaitSub(t, m, "t")
		if err := m.Publish(context.Background(), "t", []byte("k"), []byte("v")); err != nil {
			t.Fatalf("publish: %v", err)
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("record was not redelivered until the handler succeeded")
		}
		if calls.Load() != 3 {
			t.Fatalf("handler called %d times, want 3 (2 failures + 1 success)", calls.Load())
		}
		if m.HandlerErrors() != 2 {
			t.Fatalf("HandlerErrors = %d, want 2", m.HandlerErrors())
		}
		if m.HandlerLost() != 0 {
			t.Fatalf("HandlerLost = %d, want 0 (it eventually succeeded)", m.HandlerLost())
		}
	})

	t.Run("permanent_error_is_counted_lost_not_swallowed", func(t *testing.T) {
		m := NewMemory()
		defer m.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var calls atomic.Int32
		go func() {
			_ = m.Subscribe(ctx, "t", "g", func(context.Context, Message) error {
				calls.Add(1)
				return errors.New("permanent")
			})
		}()
		awaitSub(t, m, "t")
		if err := m.Publish(context.Background(), "t", []byte("k"), []byte("v")); err != nil {
			t.Fatalf("publish: %v", err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if m.HandlerLost() == 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if m.HandlerLost() != 1 {
			t.Fatalf("HandlerLost = %d, want 1 — a permanently-failing record must be counted, not silently dropped", m.HandlerLost())
		}
		// Bounded: it retried, but did not loop forever.
		if got := calls.Load(); got != memoryMaxRedeliver+1 {
			t.Fatalf("handler called %d times, want %d (initial + bounded redeliveries)", got, memoryMaxRedeliver+1)
		}
		if m.HandlerErrors() < 1 {
			t.Fatal("handler errors not counted")
		}
	})
}

func awaitSub(t *testing.T, m *Memory, topic string) {
	t.Helper()
	for i := 0; i < 200 && m.subscriberCount(topic) == 0; i++ {
		time.Sleep(time.Millisecond)
	}
	if m.subscriberCount(topic) == 0 {
		t.Fatal("subscriber never registered")
	}
}
