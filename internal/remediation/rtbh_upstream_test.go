// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"net/netip"
	"testing"
)

func TestPublishedTransitHostTemplatesKeepProviderAndFamilies(t *testing.T) {
	for _, tc := range []struct {
		id, community string
		asn           uint32
	}{
		{"ntt-gin-global-v1", "2914:666", 2914},
		{"retn-transit-v1", "9002:666", 9002},
	} {
		t.Run(tc.id, func(t *testing.T) {
			template, found := RTBHUpstreamTemplateByID(tc.id)
			if !found || template.Community != tc.community || template.SessionASN != tc.asn {
				t.Fatal("the published community is attached to the wrong transit session", template)
			}
			if !template.SupportsPrefix(netip.MustParsePrefix("192.0.2.1/32")) || !template.SupportsPrefix(netip.MustParsePrefix("2001:db8::1/128")) ||
				template.SupportsPrefix(netip.MustParsePrefix("192.0.2.0/31")) || template.SupportsPrefix(netip.MustParsePrefix("2001:db8::/127")) {
				t.Fatal("the published host templates admitted a subnet or lost a supported family", template)
			}
		})
	}
}
