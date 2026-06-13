// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// flakyWriter fails the first failN writes, then succeeds.
type flakyWriter struct {
	mu     sync.Mutex
	failN  int
	writes int
	stored []tsdb.Series
}

func (w *flakyWriter) Write(_ context.Context, s []tsdb.Series) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.writes <= w.failN {
		return errors.New("transient store failure")
	}
	w.stored = append(w.stored, s...)
	return nil
}
func (w *flakyWriter) Close() error { return nil }

func testResult(t *testing.T) (bus.Message, *resultv1.Result) {
	t.Helper()
	r := &resultv1.Result{TenantId: "t1", AgentId: "a1", CanaryType: "icmp", Success: true}
	raw, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.NetworkResultsTopic, Key: []byte("t1"), Value: raw}, r
}

func fastConsumer(b bus.Bus, w tsdb.Writer) *Consumer {
	c := NewConsumer(b, w, "test", logging.New(io.Discard, "error", "json"))
	c.retryBase = time.Microsecond
	c.sleep = func(context.Context, time.Duration) {} // compressed backoff for tests
	return c
}

// U-019: a transient store failure is retried and the record lands — zero
// loss, nothing dead-lettered.
func TestStoreWriteRetriesTransientFailure(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	w := &flakyWriter{failN: 2}
	c := fastConsumer(b, w)

	msg, _ := testResult(t)
	if err := c.handle(context.Background(), msg); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(w.stored) == 0 {
		t.Fatal("record did not land after transient failures")
	}
	st := c.Stats()
	if st.Retried != 2 || st.DeadLettered != 0 || st.Dropped != 0 {
		t.Fatalf("stats = %+v, want 2 retries, no DLQ, no drops", st)
	}
}

// U-019: when the store stays down past the retry budget, the ORIGINAL bytes
// are dead-lettered (replayable) — proven by consuming the DLQ topic and
// unmarshalling the identical result. Zero silent loss.
func TestStoreWriteExhaustionDeadLetters(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	w := &flakyWriter{failN: 1 << 30} // never recovers
	c := fastConsumer(b, w)

	got := make(chan bus.Message, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = b.Subscribe(ctx, bus.DeadLetterResultsTopic, "dlq-test", func(_ context.Context, m bus.Message) error {
			got <- m
			return nil
		})
	}()
	time.Sleep(20 * time.Millisecond) // let the memory-bus subscription attach

	msg, want := testResult(t)
	if err := c.handle(context.Background(), msg); err != nil {
		t.Fatalf("handle: %v", err)
	}

	select {
	case m := <-got:
		var r resultv1.Result
		if err := proto.Unmarshal(m.Value, &r); err != nil {
			t.Fatalf("DLQ payload not replayable: %v", err)
		}
		if r.GetTenantId() != want.GetTenantId() || r.GetAgentId() != want.GetAgentId() {
			t.Fatalf("DLQ payload mutated: %+v", &r)
		}
		if string(m.Key) != "t1" {
			t.Fatalf("DLQ key = %q, want tenant key", m.Key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("record never reached the dead-letter topic")
	}

	st := c.Stats()
	if st.DeadLettered != 1 || st.Dropped != 0 {
		t.Fatalf("stats = %+v, want exactly one dead-letter, zero drops", st)
	}
	if st.Retried != 3 {
		t.Fatalf("retried = %d, want the full budget (3)", st.Retried)
	}
}

// The only true loss — DLQ publish failing too — is COUNTED, never silent.
type deadBus struct{ bus.Bus }

func (deadBus) Publish(context.Context, string, []byte, []byte) error {
	return errors.New("bus down")
}

func TestDLQPublishFailureIsCountedLoss(t *testing.T) {
	c := fastConsumer(deadBus{Bus: bus.NewMemory()}, &flakyWriter{failN: 1 << 30})
	msg, _ := testResult(t)
	// CORRECT-001: when the store is exhausted AND the DLQ publish also fails,
	// the record is NOT safely handled. handle must return the error so the bus
	// leaves the offset UNCOMMITTED and the record is redelivered — not commit it
	// and silently rely on the (also-failing) DLQ. The loss is still counted.
	if err := c.handle(context.Background(), msg); err == nil {
		t.Fatal("handle returned nil on true loss — the offset would commit and the record would be lost")
	}
	if st := c.Stats(); st.Dropped != 1 {
		t.Fatalf("stats = %+v, want the loss counted", st)
	}
}

// A canceled context stops the retry loop promptly (no shutdown hang).
func TestRetryRespectsContextCancel(t *testing.T) {
	c := NewConsumer(bus.NewMemory(), &flakyWriter{failN: 1 << 30}, "test", logging.New(io.Discard, "error", "json"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_ = c.writeWithRetry(ctx, []tsdb.Series{{Metric: "m"}})
	if time.Since(start) > time.Second {
		t.Fatal("retry loop ignored context cancellation")
	}
}
