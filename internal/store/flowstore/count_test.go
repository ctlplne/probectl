// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"math"
	"testing"
)

// TestChCountCapsInsteadOfWrapping pins the count() reader used by tenant
// deletion, export and subject erasure: a UInt64 count is read exactly up to
// math.MaxInt64 and capped there, where a plain int64 conversion would have
// wrapped it negative and corrupted a "remaining" or "exported" figure.
func TestChCountCapsInsteadOfWrapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want int64
	}{
		{name: "zero", in: json.Number("0"), want: 0},
		{name: "json number count", in: json.Number("42"), want: 42},
		{name: "text count", in: "42", want: 42},
		{name: "past float64 precision", in: json.Number("9007199254740993"), want: 9007199254740993},
		{name: "int64 ceiling", in: json.Number("9223372036854775807"), want: math.MaxInt64},
		{name: "one past the ceiling caps", in: json.Number("9223372036854775808"), want: math.MaxInt64},
		{name: "uint64 ceiling caps", in: "18446744073709551615", want: math.MaxInt64},
		{name: "missing", in: nil, want: 0},
	} {
		if got := chCount(tc.in); got != tc.want {
			t.Errorf("%s: chCount(%v) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}
