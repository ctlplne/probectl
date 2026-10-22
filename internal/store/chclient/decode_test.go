// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"encoding/json"
	"math"
	"testing"
)

func TestDecodePreservesUInt64Precision(t *testing.T) {
	rows, err := Decode([]byte(`{"n":9007199254740993,"s":"9007199254740995"}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Uint64(rows[0]["n"]); got != 9007199254740993 {
		t.Fatalf("numeric UInt64 decoded as %d, want exact 9007199254740993", got)
	}
	if got := Uint64(rows[0]["s"]); got != 9007199254740995 {
		t.Fatalf("string UInt64 decoded as %d, want exact 9007199254740995", got)
	}
	if got := Float(rows[0]["n"]); got == 0 {
		t.Fatal("Float compatibility path returned zero for json.Number")
	}
}

// TestUint32ParsesAtTheColumnWidth pins the mpls_labels element reader:
// integer text (what Decode yields for a UInt32 array) is parsed at 32 bits,
// and every input reads as the low 32 bits of Uint64's reading, so a form
// wider than UInt32 is truncated exactly as the plain conversion truncated it.
func TestUint32ParsesAtTheColumnWidth(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want uint32
	}{
		{name: "json number", in: json.Number("16001"), want: 16001},
		{name: "uint32 ceiling", in: json.Number("4294967295"), want: math.MaxUint32},
		{name: "text", in: "7", want: 7},
		{name: "float", in: float64(16001), want: 16001},
		{name: "go integer", in: uint64(5), want: 5},
		{name: "one past the ceiling keeps the low bits", in: json.Number("4294967296"), want: 0},
		{name: "two past the ceiling keeps the low bits", in: json.Number("4294967297"), want: 1},
		{name: "wide go integer keeps the low bits", in: uint64(1<<32 + 9), want: 9},
		{name: "not a number", in: "label", want: 0},
		{name: "missing", in: nil, want: 0},
	} {
		got := Uint32(tc.in)
		if got != tc.want {
			t.Errorf("%s: Uint32(%v) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
		if low := uint32(Uint64(tc.in) & math.MaxUint32); got != low {
			t.Errorf("%s: Uint32(%v) = %d, but the low 32 bits of Uint64 are %d", tc.name, tc.in, got, low)
		}
	}

	rows, err := Decode([]byte(`{"mpls_labels":[16001,4294967295]}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := UintSlice(rows[0]["mpls_labels"]); len(got) != 2 || got[0] != 16001 || got[1] != math.MaxUint32 {
		t.Fatalf("UintSlice = %v, want [16001 4294967295]", got)
	}
	if got := UintSlice("not an array"); got != nil {
		t.Fatalf("UintSlice of a non-array = %v, want nil", got)
	}
}
