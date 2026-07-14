// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import "testing"

func TestTenantFromKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
		want string
	}{
		{name: "plain", key: []byte("tenant-a"), want: "tenant-a"},
		{name: "bucketed", key: TenantKey("tenant-a", "collector-1"), want: "tenant-a"},
		{name: "malformed bucket fails closed", key: []byte("tenant-a|bz"), want: "tenant-a|bz"},
		{name: "embedded delimiter is not suffix", key: []byte("tenant|ba-extra"), want: "tenant|ba-extra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TenantFromKey(tc.key); got != tc.want {
				t.Fatalf("TenantFromKey(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}
