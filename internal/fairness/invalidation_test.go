// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package fairness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The source captures an old value before a provider write, then returns it
// only after Invalidate. This ordering needs no scheduler race or longer TTL.
type invalidatedPolicySource struct {
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	reads   int
	before  Policy
	after   Policy
	failed  bool
}

func (s *invalidatedPolicySource) PolicyFor(ctx context.Context, tenant string) (Policy, bool, error) {
	if tenant == "blue" {
		return Policy{ResultsPerSec: 7}, true, nil
	}
	s.mu.Lock()
	s.reads++
	first := s.reads == 1
	s.mu.Unlock()
	if first {
		close(s.entered)
		select {
		case <-ctx.Done():
			return Policy{}, false, ctx.Err()
		case <-s.release:
			return s.before, true, nil
		}
	}
	if s.failed {
		return Policy{}, false, errors.New("owned policy-store outage")
	}
	return s.after, true, nil
}

func TestInvalidationDiscardsPolicyFetchAlreadyInFlight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before float64
		after  float64
		failed bool
	}{
		{name: "new_override", before: 1000, after: 50},
		{name: "tighter_override", before: 50, after: 2},
		{name: "store_outage", before: 50, after: 1000, failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &invalidatedPolicySource{entered: make(chan struct{}), release: make(chan struct{}), before: Policy{ResultsPerSec: tc.before}, after: Policy{ResultsPerSec: tc.after}, failed: tc.failed}
			var release sync.Once
			unblock := func() { release.Do(func() { close(source.release) }) }
			t.Cleanup(unblock)
			gate := NewGate(Policy{ResultsPerSec: 1000}, source).WithPolicyTTL(time.Hour)
			gate.EffectivePolicy(t.Context(), "red")
			select {
			case <-source.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("owned source did not capture the old policy")
			}
			// A slow red fetch must not block the healthy sibling tenant.
			eventually(t, func() bool { return gate.EffectivePolicy(t.Context(), "blue").ResultsPerSec == 7 })
			gate.Invalidate("red")
			gate.Invalidate("red") // repeated updates during the same old fetch
			gate.EffectivePolicy(t.Context(), "red")
			unblock()
			// Join the old refresh before requesting the current value. The
			// shard mutex is synchronization only; all policy reads use the API.
			eventually(t, func() bool {
				shard := gate.shardFor("red")
				shard.mu.Lock()
				defer shard.mu.Unlock()
				return !shard.tenants["red"].policyFetching
			})
			eventually(t, func() bool {
				policy := gate.EffectivePolicy(t.Context(), "red")
				source.mu.Lock()
				defer source.mu.Unlock()
				// A default-valued fallback is not proof of refresh completion.
				return source.reads >= 2 && policy.ResultsPerSec == tc.after
			})
			if got := gate.EffectivePolicy(t.Context(), "blue").ResultsPerSec; got != 7 {
				t.Fatal("red invalidation changed the sibling tenant", got)
			}
		})
	}
}
