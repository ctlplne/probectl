// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"testing"
	"time"
)

// ING-40: a subscriber handler PANIC used to crash the whole process. Every bus
// transport delivers records to the handler on a goroutine it spawns with no
// defer-recover above it, so a single panic (a nil-map write, an out-of-range
// index in a decode path) took down the entire control plane — and on a durable
// broker the uncommitted poison record crash-looped it on every restart.
//
// This drives the REAL in-memory bus Subscribe loop with a handler that panics
// on one record, and asserts the Subscribe goroutine SURVIVES: a SUBSEQUENT good
// record is still processed, and the panic is counted (HandlerPanics) and routed
// through the normal handler-error accounting (HandlerErrors / HandlerLost).
//
// Before the fix the panic is unrecovered in the Subscribe goroutine, which
// crashes the test PROCESS — so this test never reaches its assertions. After the
// fix the panic is recovered, the good record below is processed, and the test
// passes.
func TestMemorySurvivesHandlerPanic(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	processed := make(chan string, 2)
	go func() {
		_ = m.Subscribe(ctx, "t", "g", func(_ context.Context, msg Message) error {
			if string(msg.Value) == "poison" {
				panic("boom: injected handler panic on the poison record")
			}
			processed <- string(msg.Value)
			return nil
		})
	}()
	awaitSub(t, m, "t")

	// The panicking record. Pre-fix this crashes the Subscribe goroutine and the
	// whole process; the good record below is never seen.
	if err := m.Publish(context.Background(), "t", []byte("k"), []byte("poison")); err != nil {
		t.Fatalf("publish poison: %v", err)
	}
	// A subsequent GOOD record must still be processed — proving the subscriber
	// goroutine survived the panic and kept draining.
	if err := m.Publish(context.Background(), "t", []byte("k"), []byte("good")); err != nil {
		t.Fatalf("publish good: %v", err)
	}

	select {
	case got := <-processed:
		if got != "good" {
			t.Fatalf("processed %q, want %q after the panicking record", got, "good")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("good record never processed — the subscriber goroutine did not survive the handler panic")
	}

	if m.HandlerPanics() == 0 {
		t.Fatal("recovered panic was not counted on HandlerPanics — a recovered panic must never be silent")
	}
	// The recovered panic also flows through the bounded-redelivery accounting,
	// so the poison record is counted as a handler error and eventually lost —
	// never swallowed.
	if m.HandlerErrors() == 0 {
		t.Fatal("recovered panic not counted as a handler error (bounded-redelivery path)")
	}
	if m.HandlerLost() == 0 {
		t.Fatal("permanently-panicking record not counted as lost after its redelivery budget")
	}
}
