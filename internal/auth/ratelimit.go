// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"sync"
	"time"
)

// Limiter is the auth-endpoint brute-force guard (U-024): a failure-window
// throttle with exponential-backoff lockout, keyed by arbitrary dimensions
// (the control plane uses "ip:<addr>" and "acct:<tenant>:<email>").
//
// Semantics: attempts within Window accumulate; reaching MaxFailures locks
// the key for Lockout, doubling on each consecutive lockout (capped at
// MaxLockout) until a Success resets the key. State is in-memory and
// per-replica by design — the goal is making online brute force impractical,
// not cross-replica accounting; stale keys are swept lazily.
type Limiter struct {
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	maxLockout  time.Duration

	// OnLockout, when set, observes every lockout transition (audit seam).
	OnLockout func(key string, failures int, lockout time.Duration)

	now func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int // consecutive lockouts -> exponential backoff
	lastSeen    time.Time
}

// maxEntries bounds the table; beyond it a sweep evicts expired/stale keys
// (an attacker rotating keys cannot grow memory unboundedly).
const maxEntries = 100_000

// NewLimiter builds a Limiter. Non-positive arguments fall back to safe
// defaults: 5 failures per 1m window, 1m lockout doubling to a 1h cap.
func NewLimiter(maxFailures int, window, lockout time.Duration) *Limiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if window <= 0 {
		window = time.Minute
	}
	if lockout <= 0 {
		lockout = time.Minute
	}
	return &Limiter{
		maxFailures: maxFailures,
		window:      window,
		lockout:     lockout,
		maxLockout:  time.Hour,
		now:         time.Now,
		entries:     map[string]*entry{},
	}
}

// Allow reports whether key may proceed right now, without recording an
// attempt (the pre-check for dimensions identified mid-flow, e.g. the
// account after the IdP exchange).
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	e.lastSeen = now
	if now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// Attempt records one attempt on key and reports whether it may proceed.
// Crossing MaxFailures within Window locks the key (exponential backoff) and
// fires OnLockout once per transition.
func (l *Limiter) Attempt(key string) (bool, time.Duration) {
	l.mu.Lock()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		l.sweepLocked(now)
		e = &entry{windowStart: now}
		l.entries[key] = e
	}
	e.lastSeen = now

	if now.Before(e.lockedUntil) {
		retry := e.lockedUntil.Sub(now)
		l.mu.Unlock()
		return false, retry
	}
	if now.Sub(e.windowStart) > l.window {
		e.windowStart, e.failures = now, 0
	}
	e.failures++
	if e.failures < l.maxFailures {
		l.mu.Unlock()
		return true, 0
	}

	// Lockout transition: exponential backoff on consecutive lockouts.
	d := l.lockout << e.lockouts
	if d > l.maxLockout || d <= 0 {
		d = l.maxLockout
	}
	e.lockedUntil = now.Add(d)
	e.lockouts++
	e.failures = 0
	e.windowStart = now
	failures, hook := l.maxFailures, l.OnLockout
	l.mu.Unlock()

	if hook != nil {
		hook(key, failures, d)
	}
	return false, d
}

// Fail records a failed attempt without gating (post-identification failure
// accounting, e.g. a failed exchange attributed to an account).
func (l *Limiter) Fail(key string) { _, _ = l.Attempt(key) }

// Success clears key entirely — a legitimate login ends the backoff chain.
func (l *Limiter) Success(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// sweepLocked evicts stale entries when the table is at capacity. Caller
// holds l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	if len(l.entries) < maxEntries {
		return
	}
	stale := l.window
	if l.maxLockout > stale {
		stale = l.maxLockout
	}
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > stale && now.After(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}
