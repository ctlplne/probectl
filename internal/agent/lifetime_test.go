// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
)

// blockingCanary parks inside a measurement until the test releases it, so the
// test can observe what Run does while its goroutines are demonstrably busy.
type blockingCanary struct {
	entered chan struct{} // one send per Run entry
	release chan struct{} // closed to let every parked measurement finish
}

func (c *blockingCanary) Describe() canary.Spec {
	return canary.Spec{Type: "blocking", Version: "test", Description: "parks until released"}
}

// Run deliberately does NOT abandon on ctx cancellation: an in-flight
// measurement finishing its work after a shutdown signal is the realistic case,
// and it is exactly the case a joined Run has to wait for. The hard deadline is
// a test-hang guard, not behavior.
func (c *blockingCanary) Run(context.Context) (canary.Result, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
	case <-time.After(5 * time.Second):
	}
	return canary.Result{Type: "blocking", Target: "t", Success: true, StartedAt: time.Now()}, nil
}

// Joined lifetimes are the agent's concurrency contract (docs/architecture.md,
// "Concurrency idioms"): when a Run returns, nothing it started is still
// running. Host.Run used a raw WaitGroup — the same job in a second vocabulary
// — and the coordinator spawned bare `go co.handle(...)` calls that outlived
// it and could still be using a *Client the reconnect loop had already closed.
//
// The assertion is DIRECT rather than a goroutine count: a count settles a few
// milliseconds later whether or not Run joined, so it cannot tell a joined
// fan-out from a leaked one. Here a measurement is held open, so an unjoined
// Run returns while its work is visibly still in flight and a joined one
// cannot.
func TestHostRunJoinsEveryScheduleGoroutine(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	c := &blockingCanary{entered: make(chan struct{}, 8), release: make(chan struct{})}
	var schedules []scheduled
	for i := range 3 {
		schedules = append(schedules, scheduled{
			canary: c, interval: time.Millisecond,
			testID: "test-lifetime-" + string(rune('a'+i)),
		})
	}
	h := &Host{
		scheduled: schedules,
		buffer:    buf,
		tenantID:  "tenant-1",
		agentID:   "agent-1",
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	var returned atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
		returned.Store(true)
	}()

	select {
	case <-c.entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("no measurement started within 2s")
	}

	// Cancellation reaches the schedules, but a measurement is still parked.
	cancel()
	time.Sleep(50 * time.Millisecond)
	if returned.Load() {
		t.Fatal("Host.Run returned while a measurement was still running: the schedule goroutines " +
			"are not joined, so a canceled agent keeps probing and keeps writing into a buffer nobody drains")
	}

	close(c.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Host.Run did not return within 2s of its measurements finishing")
	}
}
