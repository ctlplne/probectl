// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
