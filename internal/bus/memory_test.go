// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"testing"
	"time"
)

// DPR-141: lag is the only counter that separates "nothing to do" from "falling
// behind" — every other integrity counter describes records the consumer already
// received, so a stalled consumer flatlines them all and looks idle.
func TestMemoryReportsConsumerLag(t *testing.T) {
	b := NewMemory()
	defer func() { _ = b.Close() }()

	// No subscribers: there is nothing to be behind on, and a zero would read as
	// a healthy consumer rather than an absent one.
	if _, n, ok := b.ConsumerLag(); ok || n != 0 {
		t.Errorf("with no subscribers want unavailable, got assignments=%d ok=%v", n, ok)
	}

	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = b.Subscribe(ctx, "t", "g", func(context.Context, Message) error {
			<-release // hold the handler so the channel accumulates depth
			return nil
		})
	}()
	waitForSubscriberCount(t, b, "t", 1)

	if _, n, ok := b.ConsumerLag(); !ok || n != 1 {
		t.Fatalf("one subscriber must be measurable: assignments=%d ok=%v", n, ok)
	}
	for i := 0; i < 3; i++ {
		if err := b.Publish(ctx, "t", nil, []byte("x")); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	var lag int64
	for time.Now().Before(deadline) {
		lag, _, _ = b.ConsumerLag()
		if lag > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lag == 0 {
		t.Error("a blocked handler with queued messages must report nonzero lag")
	}
	close(release)
}
