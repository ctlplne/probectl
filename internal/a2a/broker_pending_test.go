// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"testing"
	"time"
)

// TestBrokerReclaimsUnpolledTasksAfterTTL is the INJ-06 regression for the
// broker-side leak the mesh-cap fix (0ab6d6e) left open: gcLocked reclaimed only
// b.sessions, never b.pending, so a task queued for an agent id that never comes
// back to poll — a ghost or never-enrolled responder named in a mesh request —
// stayed in memory forever. A tenant admin could pin unbounded memory on the
// shared stateless control plane by scheduling meshes whose agents never poll.
//
// It uses only the broker's pre-existing public surface and the injectable clock
// so it asserts-red on the pre-fix tree (the stale task is still pollable past
// the TTL) rather than failing to compile. docs/guardrails.md G7-1: a stateless
// path must fail closed on memory, not grow without bound.
func TestBrokerReclaimsUnpolledTasksAfterTTL(t *testing.T) {
	b := NewBroker()
	clock := time.Unix(1_700_000_000, 0).UTC()
	b.now = func() time.Time { return clock }

	// Queue a responder task for an agent that will never poll.
	if _, err := b.StartSession("tenant-a", "ghost-responder", "initiator-1", "udp", 3); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Advance well past the 60s session TTL, then let a gc pass run (PollFor and
	// every other broker call invoke gcLocked).
	clock = clock.Add(10 * time.Minute)

	if _, ok := b.PollFor("tenant-a", "ghost-responder"); ok {
		t.Fatalf("a task for a never-polling agent was still pollable %v past the TTL: "+
			"b.pending is not reclaimed, so unpolled tasks leak until OOM (INJ-06)", 10*time.Minute)
	}
}
