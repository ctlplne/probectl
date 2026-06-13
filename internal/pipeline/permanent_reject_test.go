// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// permWriter always returns a permanent (4xx) remote-write rejection.
type permWriter struct {
	mu    sync.Mutex
	calls int
}

func (w *permWriter) Write(context.Context, []tsdb.Series) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	return fmt.Errorf("tsdb: remote-write status 400: out of order: %w", tsdb.ErrPermanentReject)
}
func (w *permWriter) Close() error { return nil }

// CORRECT-003: a permanent (4xx) remote-write rejection must NOT be retried —
// retrying an out-of-order/too-old sample can never succeed and only delays the
// DLQ. The retry loop must short-circuit on the first attempt.
func TestPermanentRejectNotRetried(t *testing.T) {
	w := &permWriter{}
	c := &Consumer{tsdb: w, maxRetries: 3, retryBase: time.Millisecond, sleep: func(context.Context, time.Duration) {}}
	err := c.writeWithRetry(context.Background(), []tsdb.Series{{Metric: "x", Value: 1, TimeMillis: 1}})
	if err == nil {
		t.Fatal("expected the permanent reject to surface as an error")
	}
	if !permanentWrite(err) {
		t.Fatalf("error lost its permanent marker: %v", err)
	}
	if w.calls != 1 {
		t.Fatalf("permanent reject was retried: %d Write calls, want exactly 1", w.calls)
	}
	if c.retried.Load() != 0 {
		t.Fatalf("retried counter moved on a permanent reject: %d, want 0", c.retried.Load())
	}
}
