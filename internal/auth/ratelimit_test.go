// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package auth

import (
	"sync"
	"testing"
	"time"
)

func testLimiter(maxFailures int, window, lockout time.Duration) (*Limiter, *time.Time) {
	l := NewLimiter(maxFailures, window, lockout)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	return l, &now
}

// U-024 brute force: the Nth attempt within the window locks the key; further
// attempts are refused with a Retry-After until the lockout expires.
func TestLimiterLockoutAfterMaxFailures(t *testing.T) {
	l, now := testLimiter(3, time.Minute, time.Minute)

	for i := 0; i < 2; i++ {
		if ok, _ := l.Attempt("ip:1.2.3.4"); !ok {
			t.Fatalf("attempt %d should pass", i+1)
		}
	}
	ok, retry := l.Attempt("ip:1.2.3.4") // 3rd = lockout transition
	if ok || retry != time.Minute {
		t.Fatalf("3rd attempt: ok=%v retry=%v, want locked for 1m", ok, retry)
	}
	if ok, _ := l.Attempt("ip:1.2.3.4"); ok {
		t.Fatal("locked key allowed an attempt")
	}
	if ok, _ := l.Allow("ip:1.2.3.4"); ok {
		t.Fatal("Allow passed a locked key")
	}
	// Another key is unaffected.
	if ok, _ := l.Attempt("ip:5.6.7.8"); !ok {
		t.Fatal("independent key throttled")
	}
	// After the lockout expires, attempts flow again.
	*now = now.Add(61 * time.Second)
	if ok, _ := l.Attempt("ip:1.2.3.4"); !ok {
		t.Fatal("expired lockout still enforced")
	}
}

// Consecutive lockouts back off exponentially and cap at MaxLockout.
func TestLimiterExponentialBackoff(t *testing.T) {
	l, now := testLimiter(1, time.Minute, time.Minute)

	wants := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}
	for _, want := range wants {
		_, retry := l.Attempt("acct:t1:a@example.com") // 1 failure = immediate lockout
		if retry != want {
			t.Fatalf("lockout = %v, want %v", retry, want)
		}
		*now = now.Add(retry + time.Second)
	}

	// Cap: drive the chain far past the 1h ceiling.
	for i := 0; i < 10; i++ {
		_, retry := l.Attempt("acct:t1:a@example.com")
		if retry > time.Hour {
			t.Fatalf("lockout %v exceeds the 1h cap", retry)
		}
		*now = now.Add(retry + time.Second)
	}
}

// A success ends the backoff chain entirely.
func TestLimiterSuccessResets(t *testing.T) {
	l, _ := testLimiter(2, time.Minute, time.Minute)
	l.Fail("ip:9.9.9.9")
	l.Success("ip:9.9.9.9")
	if ok, _ := l.Attempt("ip:9.9.9.9"); !ok {
		t.Fatal("success did not reset the failure count")
	}
}

// The window expires old failures: slow, legitimate retries never lock.
func TestLimiterWindowExpiry(t *testing.T) {
	l, now := testLimiter(3, time.Minute, time.Minute)
	for i := 0; i < 10; i++ {
		if ok, _ := l.Attempt("ip:8.8.8.8"); !ok {
			t.Fatalf("attempt %d throttled despite window expiry", i)
		}
		*now = now.Add(2 * time.Minute)
	}
}

// The lockout transition fires the audit hook exactly once per lockout.
func TestLimiterOnLockoutHook(t *testing.T) {
	l, _ := testLimiter(2, time.Minute, time.Minute)
	var mu sync.Mutex
	var calls []string
	l.OnLockout = func(key string, failures int, d time.Duration) {
		mu.Lock()
		calls = append(calls, key)
		mu.Unlock()
		if failures != 2 || d != time.Minute {
			t.Errorf("hook args: failures=%d d=%v", failures, d)
		}
	}
	l.Fail("acct:t1:bob@example.com")
	l.Fail("acct:t1:bob@example.com") // -> lockout
	l.Fail("acct:t1:bob@example.com") // already locked: no second fire
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != "acct:t1:bob@example.com" {
		t.Fatalf("hook calls = %v, want exactly one", calls)
	}
}
