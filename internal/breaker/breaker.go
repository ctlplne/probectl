// Package breaker is a minimal circuit breaker for the storage HTTP clients
// (U-078). When an upstream (Prometheus / ClickHouse) goes unreachable, the
// breaker short-circuits further calls after a failure threshold — failing
// fast with ErrOpen instead of piling up connect timeouts — and re-probes
// after a cooldown (half-open). Trips and short-circuits are counted so the
// degraded state is observable (probectl observes probectl).
package breaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrOpen is returned when a call is short-circuited by an open breaker.
var ErrOpen = errors.New("breaker: open (upstream unhealthy; short-circuited)")

// State is the breaker's current state (for metrics/diagnostics).
type State string

const (
	StateClosed   State = "closed"    // calls flow normally
	StateOpen     State = "open"      // calls short-circuit (cooldown not elapsed)
	StateHalfOpen State = "half-open" // cooldown elapsed; the next call probes
)

// Stats is a breaker snapshot.
type Stats struct {
	State          State
	Trips          uint64 // closed→open transitions
	ShortCircuits  uint64 // calls rejected without hitting the upstream
	ConsecFailures int
}

// Breaker is a single upstream's circuit breaker (safe for concurrent use).
type Breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	consec    int
	open      bool
	openUntil time.Time
	now       func() time.Time

	trips         atomic.Uint64
	shortCircuits atomic.Uint64
}

// New returns a breaker that opens after `threshold` consecutive failures and
// stays open for `cooldown`. Non-positive values get sane defaults.
func New(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

// Do runs fn unless the breaker is open. A nil error from fn is a success
// (resets/closes); a non-nil error is a failure (trips at the threshold).
// fn should return an error only for UPSTREAM-DOWN conditions (transport
// errors) — application-level responses are the caller's concern.
func (b *Breaker) Do(fn func() error) error {
	b.mu.Lock()
	if b.open && b.now().Before(b.openUntil) {
		b.mu.Unlock()
		b.shortCircuits.Add(1)
		return ErrOpen
	}
	// Closed, or open-but-cooldown-elapsed (half-open: allow this one probe).
	b.mu.Unlock()

	err := fn()

	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.consec++
		if !b.open && b.consec >= b.threshold {
			b.open = true
			b.trips.Add(1)
		}
		if b.open { // (re)arm the cooldown — covers a failed half-open probe too
			b.openUntil = b.now().Add(b.cooldown)
		}
		return err
	}
	b.consec = 0
	b.open = false
	b.openUntil = time.Time{}
	return nil
}

// Stats snapshots the breaker.
func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := StateClosed
	if b.open {
		st = StateOpen
		if !b.now().Before(b.openUntil) {
			st = StateHalfOpen
		}
	}
	return Stats{State: st, Trips: b.trips.Load(), ShortCircuits: b.shortCircuits.Load(), ConsecFailures: b.consec}
}
