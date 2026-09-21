// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import "testing"

func TestConstantTimeEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"secret-token", "secret-token", true},
		{"secret-token", "secret-tokeX", false},
		{"secret-token", "secret", false}, // different lengths
		{"", "", true},
		{"x", "", false},
	}
	for _, c := range cases {
		if got := ConstantTimeEqual([]byte(c.a), []byte(c.b)); got != c.want {
			t.Errorf("ConstantTimeEqual(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
