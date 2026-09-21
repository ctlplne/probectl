// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package wire

import (
	"errors"
	"testing"
)

func TestReaderReadsBigEndianAndLatchesFirstOverrun(t *testing.T) {
	r := New([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	if got := r.U8(); got != 1 {
		t.Fatalf("U8 = %d", got)
	}
	if got := r.U16(); got != 0x0203 {
		t.Fatalf("U16 = %#x", got)
	}
	if got := r.U32(); got != 0x04050607 {
		t.Fatalf("U32 = %#x", got)
	}
	if r.Err() != nil || !r.Empty() {
		t.Fatalf("exhausted-but-valid reader: err=%v remaining=%d", r.Err(), r.Remaining())
	}
	// One byte past the end latches; later reads are zero, not panics.
	if got := r.U8(); got != 0 {
		t.Fatalf("overrun U8 = %d, want zero value", got)
	}
	first := r.Err()
	if !errors.Is(first, ErrTruncated) {
		t.Fatalf("overrun error = %v, want ErrTruncated", first)
	}
	if got := r.U32(); got != 0 {
		t.Fatalf("read after failure = %#x, want zero value", got)
	}
	if r.Err() != first {
		t.Fatal("a later overrun replaced the FIRST error")
	}
}

func TestReaderNeverReadsBeyondItsSubFrame(t *testing.T) {
	// Outer frame: a 2-byte length then that many bytes, then a trailer the
	// inner frame must never be able to reach.
	r := New([]byte{0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD})
	inner := r.Sub(int(r.U16()))
	if got := inner.U16(); got != 0xAABB {
		t.Fatalf("inner U16 = %#x", got)
	}
	if got := inner.U8(); got != 0 || !errors.Is(inner.Err(), ErrTruncated) {
		t.Fatalf("inner read past its frame: got %#x err=%v", got, inner.Err())
	}
	// The parent is undamaged and still sees the trailer.
	if r.Err() != nil {
		t.Fatalf("inner overrun corrupted the parent: %v", r.Err())
	}
	if got := r.U16(); got != 0xCCDD {
		t.Fatalf("parent trailer = %#x, want 0xCCDD", got)
	}
}

func TestReaderSubBeyondInputFailsClosed(t *testing.T) {
	r := New([]byte{0x01})
	inner := r.Sub(64)
	if inner.Err() == nil {
		t.Fatal("over-long sub-reader must fail closed, not borrow the parent's bytes")
	}
	if got := inner.U8(); got != 0 {
		t.Fatalf("failed sub-reader returned %#x", got)
	}
	if r.Err() == nil {
		t.Fatal("the parent must record the truncation too")
	}
}

func TestReaderRejectsNegativeLength(t *testing.T) {
	r := New([]byte{1, 2, 3})
	if got := r.Bytes(-1); got != nil || r.Err() == nil {
		t.Fatalf("negative length: got %v err=%v", got, r.Err())
	}
}

func TestReaderArraysAreValues(t *testing.T) {
	r := New([]byte{10, 0, 0, 1, 192, 0, 2})
	if got := r.Array4(); got != [4]byte{10, 0, 0, 1} {
		t.Fatalf("Array4 = %v", got)
	}
	if r.Err() != nil {
		t.Fatal(r.Err())
	}
	// A short trailing address yields the zero value and latches, never panics.
	if got := r.Array4(); got != [4]byte{} || r.Err() == nil {
		t.Fatalf("Array4 past end = %v err=%v", got, r.Err())
	}
}

func TestBytesAlignedConsumesXDRPadding(t *testing.T) {
	// A 3-byte opaque field is padded to 4; the next field must start after
	// the pad, not inside it (the sFlow XDR rule this preserves).
	r := New([]byte{0xDE, 0xAD, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44})
	got := r.BytesAligned(3, 4)
	if string(got) != string([]byte{0xDE, 0xAD, 0xBE}) {
		t.Fatalf("field = % x", got)
	}
	if next := r.U32(); next != 0x11223344 {
		t.Fatalf("next field = %#x — padding was not consumed", next)
	}
	// A field whose padding runs past the end is tolerated (the sender may
	// legitimately omit trailing pad), never an error.
	r2 := New([]byte{0xAA, 0xBB, 0xCC})
	if got := r2.BytesAligned(3, 4); len(got) != 3 || r2.Err() != nil {
		t.Fatalf("trailing unpadded field: got % x err=%v", got, r2.Err())
	}
}
