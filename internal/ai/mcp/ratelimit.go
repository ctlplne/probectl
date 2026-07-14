// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mcp

import (
	"sync"
	"time"
)

// rateLimiter is a simple per-tenant token bucket bounding tool-call volume so
// one tenant cannot exhaust the server (the S25 watch-out). A non-positive rate
// disables limiting.
type rateLimiter struct {
	mu      sync.Mutex
	perMin  int
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{perMin: perMin, buckets: map[string]*bucket{}, now: time.Now}
}

// allow consumes one token for the tenant, returning false when the bucket is
// empty (rate exceeded).
func (r *rateLimiter) allow(tenant string) bool {
	if r.perMin <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	capacity := float64(r.perMin)
	refillPerSec := capacity / 60.0
	now := r.now()

	b := r.buckets[tenant]
	if b == nil {
		b = &bucket{tokens: capacity, last: now}
		r.buckets[tenant] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * refillPerSec
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
