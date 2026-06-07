package bus

import (
	"context"
	"testing"
	"time"
)

// Under the DROP overflow policy, a stuck subscriber cannot deadlock the
// publisher in a burst (U-079): publishes past the buffer are dropped and
// counted, never blocked.
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
	for i := 0; i < 100 && len(m.subs["t"]) == 0; i++ {
		time.Sleep(time.Millisecond)
	}
	close(subscribed)

	// Publish far more than the buffer; with the drop policy this must return
	// promptly (no deadlock) and count the overflow.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			if err := m.Publish(context.Background(), "t", nil, []byte("x")); err != nil {
				done <- err
				return
			}
		}
		done <- nil
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
	for i := 0; i < 100 && len(m.subs["t"]) == 0; i++ {
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
