// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tsdb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingWriter struct {
	mu       sync.Mutex
	calls    int
	series   int
	sizes    []int
	failNext bool
}

func (c *countingWriter) Write(_ context.Context, s []Series) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.series += len(s)
	c.sizes = append(c.sizes, len(s))
	if c.failNext {
		return errors.New("remote-write down")
	}
	return nil
}
func (c *countingWriter) Close() error { return nil }

type globalCountingWriter struct {
	countingWriter
	globalCalls  int
	globalSeries int
}

func (g *globalCountingWriter) WriteGlobal(_ context.Context, s []Series) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.globalCalls++
	g.globalSeries += len(s)
	return nil
}

func tenantSeries(metric string) Series {
	return Series{Metric: metric, Labels: map[string]string{TenantLabel: "t"}, Value: 1, TimeMillis: 1}
}

// blockingUnderWriter holds a write open until released, recording call count.
type blockingUnderWriter struct {
	release chan struct{}
	mu      sync.Mutex
	calls   int
	series  int
}

func (w *blockingUnderWriter) Write(_ context.Context, s []Series) error {
	<-w.release
	w.mu.Lock()
	w.calls++
	w.series += len(s)
	w.mu.Unlock()
	return nil
}
func (w *blockingUnderWriter) Close() error { return nil }

// CORRECT-011: flush() runs under its own background context, so a caller whose
// context is canceled mid-flush must still learn the write's REAL outcome — the
// row landed exactly once. Pre-fix, Write returned a bare ctx.Err() the instant
// the caller canceled, even though the flush succeeded under Background, so the
// result pipeline saw a "failure" and dead-lettered a row that had already
// stored (a double-write + dead-letter). Now Write gives the in-flight batch a
// brief grace to report success before surfacing the cancel.
func TestBatchingWriterCanceledCallerSeesRealOutcomeNoDoubleWrite(t *testing.T) {
	under := &blockingUnderWriter{release: make(chan struct{})}
	bw := NewBatchingWriter(under, 1, time.Hour) // maxSeries=1 → flush triggers immediately

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- bw.Write(ctx, []Series{tenantSeries("m")})
	}()

	// Let the size-triggered flush start (it blocks inside the under-writer).
	time.Sleep(20 * time.Millisecond)
	// Cancel the caller WHILE the flush is in flight.
	cancel()
	// Release the in-flight write: it completes successfully under Background.
	close(under.release)

	select {
	case err := <-errc:
		// The write actually landed, so the caller must see success — not a
		// cancellation that would make the pipeline dead-letter a stored row.
		if err != nil {
			t.Fatalf("Write returned %v after the flush succeeded; the pipeline would dead-letter a stored row (double-write)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return")
	}

	under.mu.Lock()
	defer under.mu.Unlock()
	if under.calls != 1 {
		t.Fatalf("underlying writer called %d times, want exactly 1 (no double-write)", under.calls)
	}
}

// SCALE-001: concurrent Writes within the window coalesce into ONE underlying
// remote-write request, and every caller still gets that request's result (so
// per-message DLQ attribution is preserved).
func TestBatchingWriterCoalesces(t *testing.T) {
	under := &countingWriter{}
	bw := NewBatchingWriter(under, 500, 50*time.Millisecond)

	const n = 20
	var wg sync.WaitGroup
	var oks atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bw.Write(context.Background(), []Series{tenantSeries("m")}); err == nil {
				oks.Add(1)
			}
		}()
	}
	wg.Wait()

	if oks.Load() != n {
		t.Fatalf("callers succeeded = %d, want %d", oks.Load(), n)
	}
	under.mu.Lock()
	calls, series := under.calls, under.series
	under.mu.Unlock()
	if calls >= n {
		t.Fatalf("no coalescing: %d underlying writes for %d callers (want far fewer)", calls, n)
	}
	if series != n {
		t.Fatalf("series lost in coalescing: wrote %d, want %d", series, n)
	}
}

// SCALE-001: a size-cap trigger flushes without waiting for the timer.
func TestBatchingWriterSizeTrigger(t *testing.T) {
	under := &countingWriter{}
	bw := NewBatchingWriter(under, 3, time.Hour) // huge wait → only size can flush
	done := make(chan error, 1)
	go func() {
		done <- bw.Write(context.Background(), []Series{tenantSeries("a"), tenantSeries("b"), tenantSeries("c")})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("size-cap did not trigger a flush (still waiting on the timer)")
	}
}

func TestBatchingWriterSplitsSingleLargeWrite(t *testing.T) {
	under := &countingWriter{}
	bw := NewBatchingWriter(under, 3, time.Hour)
	series := make([]Series, 9)
	for i := range series {
		series[i] = tenantSeries("m")
		series[i].Value = float64(i)
	}
	if err := bw.Write(context.Background(), series); err != nil {
		t.Fatal(err)
	}

	under.mu.Lock()
	defer under.mu.Unlock()
	if under.calls != 3 {
		t.Fatalf("underlying calls = %d, want 3", under.calls)
	}
	for i, got := range under.sizes {
		if got != 3 {
			t.Fatalf("call %d wrote %d series, want hard cap 3; all sizes=%v", i, got, under.sizes)
		}
	}
	if under.series != len(series) {
		t.Fatalf("series written = %d, want %d", under.series, len(series))
	}
}

// SCALE-001: the underlying error reaches the caller (so the consumer DLQs it).
func TestBatchingWriterPropagatesError(t *testing.T) {
	under := &countingWriter{failNext: true}
	bw := NewBatchingWriter(under, 500, 10*time.Millisecond)
	if err := bw.Write(context.Background(), []Series{tenantSeries("m")}); err == nil {
		t.Fatal("a failed flush must surface to the caller for DLQ attribution")
	}
}

func TestBatchingWriterRejectsUnlabeledTenantSeries(t *testing.T) {
	under := &countingWriter{}
	bw := NewBatchingWriter(under, 500, 10*time.Millisecond)
	err := bw.Write(context.Background(), []Series{{Metric: "m", Value: 1}})
	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("Write without tenant_id = %v, want ErrTenantRequired", err)
	}
	under.mu.Lock()
	defer under.mu.Unlock()
	if under.calls != 0 {
		t.Fatalf("underlying writer called for rejected series: %d", under.calls)
	}
}

func TestBatchingWriterGlobalPathBypassesTenantQueue(t *testing.T) {
	under := &globalCountingWriter{}
	bw := NewBatchingWriter(under, 500, 10*time.Millisecond)
	if err := bw.WriteGlobal(context.Background(), []Series{{Metric: "probectl_self_uptime_seconds", Value: 1}}); err != nil {
		t.Fatalf("WriteGlobal: %v", err)
	}
	if err := bw.WriteGlobal(context.Background(), []Series{{Metric: "probe_up", Labels: map[string]string{TenantLabel: "t"}, Value: 1}}); !errors.Is(err, ErrGlobalTenantLabel) {
		t.Fatalf("WriteGlobal tenant-labeled series = %v, want ErrGlobalTenantLabel", err)
	}
	under.mu.Lock()
	defer under.mu.Unlock()
	if under.globalCalls != 1 || under.globalSeries != 1 {
		t.Fatalf("global path calls/series = %d/%d, want 1/1", under.globalCalls, under.globalSeries)
	}
	if under.calls != 0 {
		t.Fatalf("global path should not use tenant Write queue, calls=%d", under.calls)
	}
}
