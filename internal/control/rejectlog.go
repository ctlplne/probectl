// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// rejectionLogger keeps fail-closed rejections loud but not flooding
// (DPR-074). A view consumer that replays its lane on every restart re-rejects
// the same historical poison batches — on the lab 17 identical ERROR lines
// within one millisecond at each start — and a misconfigured producer repeats
// its rejection on every flush. The first occurrence of a (view, plane,
// tenant, agent, reason) tuple is logged at ERROR in full; repeats inside the
// window are counted and folded into one summary line when the window ends,
// so the operator still sees every distinct fault and the rate of each.
type rejectionLogger struct {
	mu     sync.Mutex
	window time.Duration
	now    func() time.Time
	seen   map[string]*rejectionState
}

type rejectionState struct {
	first      time.Time
	suppressed uint64
}

const rejectionLogWindow = time.Minute

func newRejectionLogger(window time.Duration) *rejectionLogger {
	if window <= 0 {
		window = rejectionLogWindow
	}
	return &rejectionLogger{window: window, now: time.Now, seen: map[string]*rejectionState{}}
}

// Log records one rejection of the tuple built from key and emits either the
// first-occurrence line, a window summary, or nothing.
func (r *rejectionLogger) Log(log *slog.Logger, msg string, key []string, attrs ...any) {
	if r == nil || log == nil {
		return
	}
	k := strings.Join(key, "|")
	now := r.now()
	r.mu.Lock()
	st, ok := r.seen[k]
	switch {
	case !ok:
		r.seen[k] = &rejectionState{first: now}
		r.mu.Unlock()
		log.Error(msg, append(attrs, "occurrences", 1)...)
	case now.Sub(st.first) < r.window:
		st.suppressed++
		r.mu.Unlock()
	default:
		suppressed := st.suppressed
		st.first, st.suppressed = now, 0
		r.mu.Unlock()
		log.Error(msg, append(attrs, "occurrences", suppressed+1, "suppressed_in_window", suppressed, "window", r.window.String())...)
	}
}
