// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import "testing"

func TestDropStatsTotalAddAndDelta(t *testing.T) {
	a := DropStats{DecodeFailures: 1, L4RingBufferFull: 2, L7RingBufferFull: 3, L7ActiveReadFailures: 4, L7ScopeSyncFailures: 6, Other: 5}
	if got := a.Total(); got != 21 {
		t.Fatalf("total = %d, want 21", got)
	}

	b := DropStats{DecodeFailures: 10, L4RingBufferFull: 20, L7ScopeSyncFailures: 30}
	if got := a.Add(b); got.DecodeFailures != 11 || got.L4RingBufferFull != 22 || got.L7ScopeSyncFailures != 36 || got.Total() != 81 {
		t.Fatalf("add = %+v, want field-wise sum", got)
	}

	cur := DropStats{DecodeFailures: 5, L4RingBufferFull: 1, L7ActiveReadFailures: 8, L7ScopeSyncFailures: 9}
	prev := DropStats{DecodeFailures: 2, L4RingBufferFull: 7, L7ActiveReadFailures: 3, L7ScopeSyncFailures: 4}
	if got := cur.Delta(prev); got.DecodeFailures != 3 || got.L4RingBufferFull != 0 || got.L7ActiveReadFailures != 5 || got.L7ScopeSyncFailures != 5 {
		t.Fatalf("delta = %+v, want positive field-wise movement", got)
	}
}
