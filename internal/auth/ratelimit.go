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
// not cross-replica accounting.
//
// The table is strictly bounded to maxEntries via an intrusive LRU list: each
// touched key moves to the front, and a new key inserted at capacity evicts
// the least-recently-used entry (preferring one that is not currently locked
// out) in O(1). An attacker rotating through unbounded distinct keys can
// neither grow memory past the cap nor force a full-map sweep — every
// Attempt/Allow is O(1) regardless of table size. See docs/guardrails.md G7-N.
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
	// LRU list over entries: head is most-recently-used, tail least.
	head, tail *entry
}

type entry struct {
	key         string
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int // consecutive lockouts -> exponential backoff
	lastSeen    time.Time

	// Intrusive doubly-linked LRU list pointers (guarded by Limiter.mu).
	prev, next *entry
}

// maxEntries strictly bounds the table: at capacity, inserting a new key
// evicts the least-recently-used entry first, so an attacker rotating keys can
// neither grow memory unboundedly nor force an O(n) sweep.
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
	l.touchLocked(e)
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
		e = l.insertLocked(key, now)
	} else {
		l.touchLocked(e)
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
	if e := l.entries[key]; e != nil {
		l.removeLocked(e)
	}
	l.mu.Unlock()
}

// insertLocked creates and tracks a new entry for key. When the table is at
// capacity it first evicts one entry (O(1)), so len(entries) never exceeds
// maxEntries — no full-map sweep. Caller holds l.mu.
func (l *Limiter) insertLocked(key string, now time.Time) *entry {
	if len(l.entries) >= maxEntries {
		l.evictLocked(now)
	}
	e := &entry{key: key, windowStart: now, lastSeen: now}
	l.entries[key] = e
	l.pushFrontLocked(e)
	return e
}

// evictLocked removes exactly one entry to make room, preferring the
// least-recently-used entry that is not currently locked out so an active
// lockout is not cleared by key churn. The scan from the tail is bounded to a
// small constant, keeping eviction O(1) irrespective of table size. Caller
// holds l.mu.
func (l *Limiter) evictLocked(now time.Time) {
	const scan = 8
	victim := l.tail
	for e, i := l.tail, 0; e != nil && i < scan; e, i = e.prev, i+1 {
		if !now.Before(e.lockedUntil) { // not currently locked out
			victim = e
			break
		}
	}
	if victim != nil {
		l.removeLocked(victim)
	}
}

// removeLocked unlinks e from the LRU list and drops it from the map. Caller
// holds l.mu.
func (l *Limiter) removeLocked(e *entry) {
	l.unlinkLocked(e)
	delete(l.entries, e.key)
}

// touchLocked marks e most-recently-used. Caller holds l.mu.
func (l *Limiter) touchLocked(e *entry) {
	if l.head == e {
		return
	}
	l.unlinkLocked(e)
	l.pushFrontLocked(e)
}

// pushFrontLocked inserts e at the head (most-recently-used). Caller holds
// l.mu.
func (l *Limiter) pushFrontLocked(e *entry) {
	e.prev = nil
	e.next = l.head
	if l.head != nil {
		l.head.prev = e
	}
	l.head = e
	if l.tail == nil {
		l.tail = e
	}
}

// unlinkLocked detaches e from the LRU list. Caller holds l.mu.
func (l *Limiter) unlinkLocked(e *entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if l.head == e {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if l.tail == e {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
}
