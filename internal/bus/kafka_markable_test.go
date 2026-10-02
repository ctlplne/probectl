// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"testing"

	"github.com/twmb/franz-go/pkg/kgo"
)

// TestMarkableHoldsBackAtAndAfterFirstFailure pins the ING-12 commit rule with
// no broker: markable must never return a record that would advance a
// partition's committed offset to or past a record whose handler errored —
// including a success that arrives in a LATER poll batch than the failure, which
// is the case the per-record commit got wrong.
func TestMarkableHoldsBackAtAndAfterFirstFailure(t *testing.T) {
	rec := func(part int32, off int64) *kgo.Record {
		return &kgo.Record{Topic: NetworkResultsTopic, Partition: part, Offset: off}
	}
	offsets := func(rs []*kgo.Record) map[int32][]int64 {
		out := map[int32][]int64{}
		for _, r := range rs {
			out[r.Partition] = append(out[r.Partition], r.Offset)
		}
		return out
	}
	hasOffset := func(rs []*kgo.Record, part int32, off int64) bool {
		for _, r := range rs {
			if r.Partition == part && r.Offset == off {
				return true
			}
		}
		return false
	}

	// A single long-lived subscription session: one ceiling map across batches.
	firstFail := map[topicPartition]int64{}

	// Batch 1: partition 0 offset 0 FAILS; offset 1 and 2 SUCCEED after it in the
	// same batch; partition 1 offset 0 succeeds cleanly.
	p0o0, p0o1, p0o2, p1o0 := rec(0, 0), rec(0, 1), rec(0, 2), rec(1, 0)
	marks := markable(firstFail, []recordOutcome{
		{p0o0, false}, {p0o1, true}, {p0o2, true}, {p1o0, true},
	})
	if hasOffset(marks, 0, 0) || hasOffset(marks, 0, 1) || hasOffset(marks, 0, 2) {
		t.Fatalf("a later success in partition 0 must not be committed past the failure at offset 0: marked %v", offsets(marks))
	}
	if !hasOffset(marks, 1, 0) {
		t.Fatalf("partition 1 never failed, so its clean record must be committable: marked %v", offsets(marks))
	}

	// Batch 2 (a LATER poll): partition 0 offset 3 succeeds. It must STILL be held
	// back — the failure at offset 0 is only re-fetched after a rebalance/restart,
	// so committing offset 3 would strand offset 0 forever (the cross-batch bug).
	p0o3 := rec(0, 3)
	marks = markable(firstFail, []recordOutcome{{p0o3, true}})
	if hasOffset(marks, 0, 3) {
		t.Fatalf("a success in a later batch must not commit past a prior failure in the same partition: marked %v", offsets(marks))
	}
	if len(marks) != 0 {
		t.Fatalf("partition 0 is pinned by its failure; nothing in it is committable: marked %v", offsets(marks))
	}

	// Partition 1 is unaffected and keeps committing.
	p1o1 := rec(1, 1)
	marks = markable(firstFail, []recordOutcome{{p1o1, true}})
	if !hasOffset(marks, 1, 1) || len(marks) != 1 {
		t.Fatalf("a partition with no failure must keep committing: marked %v", offsets(marks))
	}
}

// TestMarkableCommitsACleanBatch confirms the fix does not withhold commits when
// nothing failed: a batch of all-successful records is fully markable.
func TestMarkableCommitsACleanBatch(t *testing.T) {
	rec := func(part int32, off int64) *kgo.Record {
		return &kgo.Record{Topic: NetworkResultsTopic, Partition: part, Offset: off}
	}
	firstFail := map[topicPartition]int64{}
	in := []recordOutcome{
		{rec(0, 0), true}, {rec(0, 1), true}, {rec(1, 0), true},
	}
	marks := markable(firstFail, in)
	if len(marks) != 3 {
		t.Fatalf("a clean batch must be fully committable, got %d of 3", len(marks))
	}
	if len(firstFail) != 0 {
		t.Fatalf("no failure means no commit ceiling, got %v", firstFail)
	}
}
