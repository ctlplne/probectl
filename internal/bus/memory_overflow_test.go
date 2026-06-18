// SPDX-License-Identifier: LicenseRef-probectl-TBD

package bus

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Under the DROP overflow policy, a stuck subscriber cannot deadlock the
// publisher in a burst (U-079), but the loss is now returned as an error
// (RESIL-002) so upstream agent ACK paths retry instead of deleting frames.
func TestMemoryDropOverflowDoesNotBlock(t *testing.T) {
	m := NewMemory(WithBuffer(2), WithOverflowDrop())
	defer m.Close()

	// A subscriber that never drains its channel (registered but stuck).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	subscribed := make(chan struct{})
	go func() {
		_ = m.Subscribe(ctx, "t", "g", func(context.Context, Message) error {
			<-ctx.Done() // block forever inside the handler — channel fills
			return nil
		})
	}()
	// Let the subscriber register.
	for i := 0; i < 5000 && m.subscriberCount("t") == 0; i++ { // ~5s: -race-safe (cf. TestPolicyLifecycle)
		time.Sleep(time.Millisecond)
	}
	close(subscribed)

	// Publish far more than the buffer; with the drop policy this must return
	// promptly (no deadlock), count the overflow, and report it to the caller.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			if err := m.Publish(context.Background(), "t", nil, []byte("x")); err != nil {
				if errors.Is(err, ErrMemoryDropped) {
					done <- nil
					return
				}
				done <- err
				return
			}
		}
		done <- errors.New("drop policy did not report an overflow")
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("publish error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drop policy deadlocked the publisher")
	}
	if m.Dropped() == 0 {
		t.Fatal("overflow under the drop policy must be counted")
	}
}

func TestMemoryFlushWaitsForHandlers(t *testing.T) {
	m := NewMemory(WithBuffer(2))
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = m.Subscribe(ctx, "t", "g", func(context.Context, Message) error {
			close(started)
			<-release
			return nil
		})
	}()
	for i := 0; i < 5000 && m.subscriberCount("t") == 0; i++ {
		time.Sleep(time.Millisecond)
	}
	if m.subscriberCount("t") == 0 {
		t.Fatal("subscriber did not register")
	}
	if err := m.Publish(context.Background(), "t", nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	flushed := make(chan error, 1)
	go func() { flushed <- m.Flush(context.Background()) }()
	select {
	case err := <-flushed:
		t.Fatalf("Flush returned before handler completion: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-flushed:
		if err != nil {
			t.Fatalf("Flush after handler release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flush did not return after handler completion")
	}
}

// The block policy (default) keeps every message: a draining subscriber
// receives all of them, and Dropped stays zero.
func TestMemoryBlockPolicyLosesNothing(t *testing.T) {
	m := NewMemory(WithBuffer(4)) // default = block
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const n = 200
	got := make(chan int, 1)
	go func() {
		count := 0
		_ = m.Subscribe(ctx, "t", "g", func(_ context.Context, _ Message) error {
			count++
			if count == n {
				got <- count
			}
			return nil
		})
	}()
	for i := 0; i < 5000 && m.subscriberCount("t") == 0; i++ { // ~5s: -race-safe (cf. TestPolicyLifecycle)
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < n; i++ {
		if err := m.Publish(context.Background(), "t", nil, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case c := <-got:
		if c != n {
			t.Fatalf("received %d, want %d", c, n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("block policy lost messages")
	}
	if m.Dropped() != 0 {
		t.Fatalf("block policy dropped %d", m.Dropped())
	}
}

// TestMemoryDropPolicyReportsLossToPublisher is the RESIL-002 acceptance: a
// stuck subscriber may be isolated with the explicit drop policy, but the
// publisher gets ErrMemoryDropped so upstream does not ACK known loss.
func TestMemoryDropPolicyReportsLossToPublisher(t *testing.T) {
	m := NewMemory(WithBuffer(2), WithOverflowDrop())
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subscriber A: stuck forever (never drains).
	go func() {
		_ = m.Subscribe(ctx, "t", "stuck", func(context.Context, Message) error {
			<-ctx.Done()
			return nil
		})
	}()
	// Subscriber B: drains normally and counts what it receives.
	const n = 500
	var received atomic.Uint64
	go func() {
		_ = m.Subscribe(ctx, "t", "drainer", func(context.Context, Message) error {
			received.Add(1)
			return nil
		})
	}()
	for i := 0; i < 5000 && m.subscriberCount("t") < 2; i++ { // ~5s: -race-safe
		time.Sleep(time.Millisecond)
	}
	if m.subscriberCount("t") < 2 {
		t.Fatal("both subscribers did not register")
	}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			if err := m.Publish(context.Background(), "t", nil, []byte("x")); err != nil {
				done <- err
				return
			}
			time.Sleep(100 * time.Microsecond)
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrMemoryDropped) {
			t.Fatalf("drop policy publish error = %v, want ErrMemoryDropped", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("drop policy blocked instead of returning ErrMemoryDropped")
	}
	if m.Dropped() == 0 {
		t.Fatal("drop policy returned ErrMemoryDropped but did not count the drop")
	}
	deadline := time.Now().Add(time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := received.Load(); got == 0 {
		t.Fatal("draining subscriber made no progress before the stuck lane overflowed")
	}
}
