// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Consumer-group semantics for the lightweight bus (Foundation-Loop
// S-901480ab).
//
// The in-memory bus used to discard the group argument, so every subscriber
// received every message. Lightweight mode is a shipped deployment option, so
// that made every statement about independent offsets or replay isolation
// Kafka-only — and made the two buses disagree about what a second consumer
// on a topic MEANS.
//
// The contract, stated once and asserted below: a message reaches every GROUP,
// and exactly one member WITHIN a group.

// collectingSub joins a group and records what it receives.
type collectingSub struct {
	mu   sync.Mutex
	got  []string
	done chan struct{}
}

func (s *collectingSub) handle(_ context.Context, msg Message) error {
	s.mu.Lock()
	s.got = append(s.got, string(msg.Value))
	n := len(s.got)
	s.mu.Unlock()
	if n == 1 {
		select {
		case <-s.done:
		default:
		}
	}
	return nil
}

func (s *collectingSub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// TestMemoryBusDeliversOncePerGroup: two members of one group split the topic;
// a member of a second group receives all of it.
func TestMemoryBusDeliversOncePerGroup(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a1, a2, b1 := &collectingSub{}, &collectingSub{}, &collectingSub{}
	var wg sync.WaitGroup
	for _, sub := range []struct {
		group string
		s     *collectingSub
	}{{"group-a", a1}, {"group-a", a2}, {"group-b", b1}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Subscribe(ctx, "t", sub.group, sub.s.handle)
		}()
	}
	if !m.WaitForSubscribers(ctx, "t", 3) {
		t.Fatal("subscribers never registered")
	}

	const messages = 10
	for i := range messages {
		if err := m.Publish(ctx, "t", nil, fmt.Appendf(nil, "msg-%d", i)); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	if err := m.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if got := a1.count() + a2.count(); got != messages {
		t.Errorf("group-a received %d messages across its two members, want %d: "+
			"members of one group must SPLIT the topic, not each get a full copy", got, messages)
	}
	if a1.count() == 0 || a2.count() == 0 {
		t.Errorf("group-a split %d/%d: every member must get a share, or one consumer "+
			"is dead weight that still counts as capacity", a1.count(), a2.count())
	}
	if got := b1.count(); got != messages {
		t.Errorf("group-b received %d, want %d: a SEPARATE group must receive the whole topic", got, messages)
	}

	cancel()
	wg.Wait()
}

// A group that leaves must stop being a delivery target, and a rejoining group
// must not inherit a stale round-robin cursor.
func TestMemoryBusForgetsDepartedGroups(t *testing.T) {
	m := NewMemory()
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	leaveCtx, leave := context.WithCancel(ctx)
	gone := make(chan struct{})
	transient := &collectingSub{}
	go func() {
		defer close(gone)
		_ = m.Subscribe(leaveCtx, "t", "transient", transient.handle)
	}()
	if !m.WaitForSubscribers(ctx, "t", 1) {
		t.Fatal("subscriber never registered")
	}
	leave()
	<-gone
	waitForSubscriberCount(t, m, "t", 0)

	// With no subscribers left, a publish must not block or error in block
	// mode: there is no member to deliver to.
	pubCtx, pubCancel := context.WithTimeout(ctx, 2*time.Second)
	defer pubCancel()
	if err := m.Publish(pubCtx, "t", nil, []byte("after-departure")); err != nil {
		t.Fatalf("publish after the only group left: %v", err)
	}

	// Rejoining must receive subsequent traffic normally.
	rejoined := &collectingSub{}
	go func() { _ = m.Subscribe(ctx, "t", "transient", rejoined.handle) }()
	if !m.WaitForSubscribers(ctx, "t", 1) {
		t.Fatal("rejoined subscriber never registered")
	}
	if err := m.Publish(ctx, "t", nil, []byte("after-rejoin")); err != nil {
		t.Fatalf("publish after rejoin: %v", err)
	}
	if err := m.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rejoined.count() != 1 {
		t.Errorf("rejoined member received %d messages, want 1", rejoined.count())
	}
	if transient.count() != 0 {
		t.Errorf("departed member received %d messages after leaving, want 0", transient.count())
	}
}

func waitForSubscriberCount(t *testing.T, m *Memory, topic string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.subscriberCount(topic) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("subscriber count on %q never reached %d (now %d)", topic, want, m.subscriberCount(topic))
}
