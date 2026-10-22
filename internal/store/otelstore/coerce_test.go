// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otelstore

import (
	"math"
	"strconv"
	"testing"
)

// TestI32ParsesAtTheColumnWidth pins the severity_num reader: ClickHouse
// renders an Int32 as a JSON number, decoded as float64, and numeric text is
// parsed at 32 bits, so no reading is cut down from a wider parse.
func TestI32ParsesAtTheColumnWidth(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want int32
	}{
		{name: "json number", in: float64(17), want: 17},
		{name: "negative json number", in: float64(-3), want: -3},
		{name: "text", in: "9", want: 9},
		{name: "text at the int32 ceiling", in: "2147483647", want: math.MaxInt32},
		{name: "text at the int32 floor", in: "-2147483648", want: math.MinInt32},
		{name: "text wider than int32 saturates", in: "2147483648", want: math.MaxInt32},
		{name: "text narrower than int32 saturates", in: "-2147483649", want: math.MinInt32},
		{name: "not a number", in: "warn", want: 0},
		{name: "missing", in: nil, want: 0},
	} {
		if got := i32(tc.in); got != tc.want {
			t.Errorf("%s: i32(%v) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestCountOfReadsCountsWithoutNarrowing pins the erase-verification count
// reader: the UInt64 count() arrives as decimal text and is parsed straight to
// int, exactly as the 64-bit parse read it, never through a narrowing.
func TestCountOfReadsCountsWithoutNarrowing(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want int
	}{
		{name: "zero", in: "0", want: 0},
		{name: "text count", in: "42", want: 42},
		{name: "json number count", in: float64(42), want: 42},
		{name: "not a number", in: "n/a", want: 0},
		{name: "missing", in: nil, want: 0},
	} {
		if got := countOf(tc.in); got != tc.want {
			t.Errorf("%s: countOf(%v) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
	if strconv.IntSize == 64 {
		// Past float64's exact range and past int32: read exactly, as i64 did.
		const big = "9007199254740993"
		if got := countOf(big); strconv.Itoa(got) != big || int64(got) != i64(big) {
			t.Errorf("countOf(%s) = %d, want it exact", big, got)
		}
	}
}
