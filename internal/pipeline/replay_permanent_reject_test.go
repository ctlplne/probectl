// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// permanentRejectWriter always fails the TSDB write with ErrPermanentReject,
// mirroring prometheus.go's 4xx ("out of order sample") classification — a
// write the server will NEVER accept.
type permanentRejectWriter struct{ writes atomic.Int64 }

func (w *permanentRejectWriter) Write(context.Context, []tsdb.Series) error {
	w.writes.Add(1)
	return fmt.Errorf("tsdb: remote-write status 400: out of order sample: %w", tsdb.ErrPermanentReject)
}
func (w *permanentRejectWriter) Close() error { return nil }

// TestDeadLetterReplayTerminatesOnPermanentReject is the RTO-17 regression: a
// record the store PERMANENTLY rejects must be routed terminally, never
// re-queued to the replayable dead-letter topic. It drives the REAL consumer +
// REAL replayer over the in-process bus (no external Kafka/Prometheus), with a
// fake TSDB that always returns tsdb.ErrPermanentReject:
//
//   - the live consumer subscribes to the SOURCE topic and runs c.handle;
//   - the replayer drains the DLQ and re-publishes each record to the source;
//   - a separate-group subscriber counts every record that reaches the DLQ.
//
// Pre-fix the consumer re-queued each permanent reject onto the DLQ, so the
// round trip looped forever: the replayer never went idle, the DLQ grew without
// bound, and the permanent-reject count climbed per pass. The assertions below
// fail on that behavior (replay never terminates within the bound / DLQ grows /
// count != N) and pass once permanent rejects are terminal.
func TestDeadLetterReplayTerminatesOnPermanentReject(t *testing.T) {
	const (
		n     = 5
		idle  = 400 * time.Millisecond
		bound = 3 * time.Second
	)

	b := bus.NewMemory()
	defer b.Close()

	w := &permanentRejectWriter{}
	c := fastConsumer(b, w)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	var wg sync.WaitGroup

	// Live consumer on the SOURCE topic: the REAL ingest path. A permanent reject
	// here is where the pre-fix code re-queued the record to the DLQ.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = b.Subscribe(rootCtx, bus.NetworkResultsTopic, "rto17-consumer", func(hctx context.Context, m bus.Message) error {
			return c.handle(hctx, m)
		})
	}()

	// Count every record that lands on the DLQ. A distinct group gets its own
	// copy, so it observes DLQ traffic without stealing from the replayer.
	var dlqSeen atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = b.Subscribe(rootCtx, bus.DeadLetterResultsTopic, "rto17-dlq-counter", func(_ context.Context, _ bus.Message) error {
			dlqSeen.Add(1)
			return nil
		})
	}()

	// Replayer: drains the DLQ → re-publishes verbatim to the source topic.
	// allowAllBinding satisfies the legacy-results re-verification — the subject
	// here is the replay loop, not the refusal path.
	r := NewDeadLetterReplayer(b, testLogger()).WithBinding(allowAllBinding{})
	replayDone := make(chan ReplayResult, 1)
	replayErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := r.Replay(rootCtx, ReplayConfig{
			DLQTopic:    bus.DeadLetterResultsTopic,
			IdleTimeout: idle,
		})
		replayErr <- err
		replayDone <- res
	}()

	// Live pub/sub only delivers to subscribers present at publish time: wait for
	// the consumer (source) and BOTH DLQ subscribers (counter + replayer) to
	// register before seeding.
	waitCtx, waitCancel := context.WithTimeout(rootCtx, 2*time.Second)
	if !b.WaitForSubscribers(waitCtx, bus.NetworkResultsTopic, 1) ||
		!b.WaitForSubscribers(waitCtx, bus.DeadLetterResultsTopic, 2) {
		waitCancel()
		t.Fatal("subscribers did not register before the readiness deadline")
	}
	waitCancel()

	// Seed N permanently-rejectable records onto the DLQ.
	for i := 0; i < n; i++ {
		msg, _ := testResult(t)
		if err := b.Publish(rootCtx, bus.DeadLetterResultsTopic, msg.Key, msg.Value); err != nil {
			t.Fatalf("seed DLQ record %d: %v", i, err)
		}
	}

	// ASSERTION 1 — replay TERMINATES on idle within the bound. Pre-fix it never
	// goes idle: the consumer keeps re-queuing rejects, so the drain only returns
	// when rootCtx is canceled at the bound — which this treats as a failure.
	select {
	case res := <-replayDone:
		if err := <-replayErr; err != nil {
			t.Fatalf("replay returned error: %v", err)
		}
		if res.Replayed != n {
			t.Fatalf("replayed count = %d, want exactly %d (each seed drained once)", res.Replayed, n)
		}
	case <-time.After(bound):
		t.Fatalf("replay did NOT terminate within %s: dead-letter replay looped on permanently-rejected records "+
			"(DLQ records seen=%d, store write attempts=%d)", bound, dlqSeen.Load(), w.writes.Load())
	}

	// The consumer finishes the drained records just behind the replayer; give it
	// a bounded moment to settle before reading its counters.
	deadline := time.Now().Add(2 * time.Second)
	for c.Stats().TerminallyRejected < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// ASSERTION 2 — no DLQ amplification: only the N seeds ever reached the DLQ
	// (the consumer re-queued nothing). Pre-fix this climbs far past N.
	if got := dlqSeen.Load(); got > int64(n) {
		t.Fatalf("DLQ saw %d records, want <= %d — replay amplified the dead-letter queue", got, n)
	}

	// ASSERTION 3 — each permanently-rejected record is counted EXACTLY once, and
	// none were parked on the replayable DLQ.
	st := c.Stats()
	if st.TerminallyRejected != n {
		t.Fatalf("terminally-rejected count = %d, want exactly %d (counted once per record)", st.TerminallyRejected, n)
	}
	if st.DeadLettered != 0 {
		t.Fatalf("dead-lettered count = %d, want 0 — a permanent reject must not be re-queued as replayable", st.DeadLettered)
	}

	rootCancel()
	wg.Wait()
}
