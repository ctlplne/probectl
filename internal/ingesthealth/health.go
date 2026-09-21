// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package ingesthealth provides bounded, payload-free observability for live
// ingestion boundaries. It deliberately accepts only a fixed failure class:
// callers cannot accidentally pass an untrusted error or record into a log.
package ingesthealth

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const defaultLogInterval = time.Minute

// Class is a safe, bounded classification for a failed live-ingestion record.
type Class string

const (
	ClassRejected          Class = "rejected"
	ClassParseFailed       Class = "parse_failed"
	ClassRateLimited       Class = "rate_limited"
	ClassPersistenceFailed Class = "persistence_failed"
)

// Snapshot is a point-in-time copy of one listener's monotonic counters.
type Snapshot struct {
	Accepted          uint64 `json:"accepted"`
	Rejected          uint64 `json:"rejected"`
	ParseFailed       uint64 `json:"parse_failed"`
	RateLimited       uint64 `json:"rate_limited"`
	PersistenceFailed uint64 `json:"persistence_failed"`
}

type logState struct {
	logged     bool
	last       time.Time
	suppressed uint64
}

// Monitor owns monotonic counters and emits at most one structured warning per
// failure class per interval. Log fields are fixed here so record bodies,
// packets, credentials, signatures, and underlying error strings cannot leak.
type Monitor struct {
	tenantID string
	listener string
	log      *slog.Logger
	now      func() time.Time

	accepted          atomic.Uint64
	rejected          atomic.Uint64
	parseFailed       atomic.Uint64
	rateLimited       atomic.Uint64
	persistenceFailed atomic.Uint64

	logMu    sync.Mutex
	logState [4]logState
}

// New constructs a listener health monitor. A nil logger uses slog.Default.
func New(tenantID, listener string, log *slog.Logger, now func() time.Time) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Monitor{
		tenantID: tenantID,
		listener: listener,
		log:      log,
		now:      now,
	}
}

// ObserveAccepted increments the successfully persisted record count.
func (m *Monitor) ObserveAccepted() {
	m.accepted.Add(1)
}

// ObserveFailure increments class and emits a bounded, payload-free warning.
func (m *Monitor) ObserveFailure(class Class) {
	counter, index, ok := m.failureCounter(class)
	if !ok {
		return
	}
	total := counter.Add(1)
	now := m.now()

	m.logMu.Lock()
	state := &m.logState[index]
	if state.logged && now.Sub(state.last) < defaultLogInterval {
		state.suppressed++
		m.logMu.Unlock()
		return
	}
	suppressed := state.suppressed
	state.logged = true
	state.last = now
	state.suppressed = 0
	m.logMu.Unlock()

	m.log.Warn(
		"live ingestion record failed",
		"tenant_id", m.tenantID,
		"listener", m.listener,
		"error_class", string(class),
		"failures_total", total,
		"suppressed_since_last", suppressed,
	)
}

// Snapshot returns an atomic point-in-time copy of the listener counters.
func (m *Monitor) Snapshot() Snapshot {
	return Snapshot{
		Accepted:          m.accepted.Load(),
		Rejected:          m.rejected.Load(),
		ParseFailed:       m.parseFailed.Load(),
		RateLimited:       m.rateLimited.Load(),
		PersistenceFailed: m.persistenceFailed.Load(),
	}
}

func (m *Monitor) failureCounter(class Class) (*atomic.Uint64, int, bool) {
	switch class {
	case ClassRejected:
		return &m.rejected, 0, true
	case ClassParseFailed:
		return &m.parseFailed, 1, true
	case ClassRateLimited:
		return &m.rateLimited, 2, true
	case ClassPersistenceFailed:
		return &m.persistenceFailed, 3, true
	default:
		return nil, 0, false
	}
}
