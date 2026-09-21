// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
