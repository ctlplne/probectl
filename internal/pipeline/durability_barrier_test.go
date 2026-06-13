// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// blockingWriter lets a test hold a write open, then release it, and records
// whether the series landed BEFORE the handler returned.
type blockingWriter struct {
	release chan struct{}
	mu      sync.Mutex
	stored  []tsdb.Series
}

func (w *blockingWriter) Write(ctx context.Context, s []tsdb.Series) error {
	select {
	case <-w.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	w.mu.Lock()
	w.stored = append(w.stored, s...)
	w.mu.Unlock()
	return nil
}
func (w *blockingWriter) Close() error { return nil }
func (w *blockingWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.stored)
}

// startDecoupledStage stands up the decoupled write stage exactly as Run does
// (one worker pool draining writeCh), so a unit test can exercise the
// handler→writeCh→worker durability barrier without a full subscription loop.
func startDecoupledStage(t *testing.T, c *Consumer, ctx context.Context, workers int) func() {
	t.Helper()
	c.writeCh = make(chan writeItem, workers*16)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range c.writeCh {
				it.done <- c.writeOne(ctx, it)
			}
		}()
	}
	return func() {
		close(c.writeCh)
		wg.Wait()
		c.writeCh = nil
	}
}

// CORRECT-001: on the decoupled (production) path the offset must commit only
// AFTER the durable write. handle therefore must not return until the write
// stage has reported the record durable-or-dead-lettered. This test proves the
// handler BLOCKS on the in-flight write and only sees the record stored once the
// write actually completes — i.e. the offset can never advance ahead of the
// store write.
func TestDecoupledHandlerWaitsForDurableWrite(t *testing.T) {
	w := &blockingWriter{release: make(chan struct{})}
	c := NewConsumer(bus.NewMemory(), w, "test", logging.New(io.Discard, "error", "json"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startDecoupledStage(t, c, ctx, 2)
	defer stop()

	msg := resultMsg(t, "t1", "a1")
	returned := make(chan error, 1)
	go func() { returned <- c.handle(ctx, msg) }()

	// The handler must still be blocked: nothing is stored and it has not
	// returned, because the write is held open.
	time.Sleep(20 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("handle returned (%v) before the write was durable — offset would commit ahead of the store", err)
	default:
	}
	if w.count() != 0 {
		t.Fatal("write happened without releasing — test setup wrong")
	}

	// Release the write; only now may the handler return (offset commit).
	close(w.release)
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("handle returned an error on a durable write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not return after the write completed")
	}
	if w.count() == 0 {
		t.Fatal("handle returned nil but nothing was stored")
	}
}

// CORRECT-001: if the write is exhausted AND the DLQ publish also fails (true
// loss) on the decoupled path, the handler must return a non-nil error so the
// bus leaves the offset UNCOMMITTED and the record is redelivered, never
// committed-then-lost. The loss is also counted.
func TestDecoupledTrueLossDoesNotCommit(t *testing.T) {
	c := NewConsumer(deadBus{Bus: bus.NewMemory()}, alwaysFailWriter{}, "test", logging.New(io.Discard, "error", "json"))
	c.retryBase = time.Microsecond
	c.sleep = func(context.Context, time.Duration) {}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startDecoupledStage(t, c, ctx, 1)
	defer stop()

	err := c.handle(ctx, resultMsg(t, "t1", "a1"))
	if err == nil {
		t.Fatal("handle returned nil on true loss — the offset would commit and the record would be lost")
	}
	if c.Stats().Dropped != 1 {
		t.Fatalf("expected the loss counted once, stats=%+v", c.Stats())
	}
}
