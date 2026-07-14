// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import "testing"

// SCALE-001: sharding is deterministic (same key → same shard, preserving
// per-key order) and spreads distinct keys across workers.
func TestConsumeShardKeyOrdering(t *testing.T) {
	const workers = 8
	if a, b := shardKey([]byte("tenant-a"))%workers, shardKey([]byte("tenant-a"))%workers; a != b {
		t.Fatal("same key must always land on the same shard (per-key FIFO)")
	}
	seen := map[uint32]bool{}
	for _, k := range []string{"t-1", "t-2", "t-3", "t-4", "t-5", "t-6", "t-7", "t-8", "t-9", "t-10"} {
		seen[shardKey([]byte(k))%workers] = true
	}
	if len(seen) < 3 {
		t.Fatalf("distinct keys collapsed onto %d shard(s) — no parallelism", len(seen))
	}
	// Key-less records all share one shard (conservative global order).
	if shardKey(nil)%workers != shardKey([]byte{})%workers {
		t.Fatal("empty-key records must share a shard")
	}
}
