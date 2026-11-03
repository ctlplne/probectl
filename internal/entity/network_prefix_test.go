// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"testing"
)

func TestExplicitNetworkPrefixIsTypedAndIndependentOfLabels(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""}, {"10.2.0.7/24", "10.2.0.0/24"},
		{" 2001:db8:2::9/48 ", "2001:db8:2::/48"},
		{"0.0.0.0/0", "0.0.0.0/0"}, {"::/0", "::/0"},
	} {
		if got, err := NormalizeNetworkPrefix(Prefix, tc.input); err != nil || got != tc.want {
			t.Fatalf("explicit network normalization: %q %v", got, err)
		}
	}
	for _, input := range []string{"10.2.0.1", "router.example/24", "fe80::1%eth0/64", "10.2.0.0/33"} {
		if _, err := NormalizeNetworkPrefix(Prefix, input); !errors.Is(err, ErrInvalidClaim) {
			t.Fatal("non-network input became a prefix fact")
		}
	}
	for _, kind := range []Kind{Device, Interface, Address, Service, Site, Customer} {
		if _, err := NormalizeNetworkPrefix(kind, "10.2.0.0/24"); !errors.Is(err, ErrInvalidClaim) {
			t.Fatal("network metadata crossed the prefix kind boundary")
		}
	}
}
