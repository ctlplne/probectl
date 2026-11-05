// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"net/netip"
	"testing"
)

func TestSubjectAddressAliasesRequireExplicitIPSubject(t *testing.T) {
	identity := newSubjectAliasSet("actual-user")
	identity.add("192.0.2.7") // An IP-shaped username is still an identity alias.
	identity.add("2001:db8::7")
	if len(identity.addresses) != 0 {
		t.Fatal("identity aliases acquired network address authority")
	}
	for _, input := range []string{"192.0.2.7", "::ffff:192.0.2.7", "2001:0db8:0:0:0:0:0:7"} {
		aliases := newSubjectAliasSet(input)
		want := netip.MustParseAddr(input).Unmap()
		if len(aliases.addresses) != 1 || aliases.addresses[0] != want {
			t.Fatal("explicit IP subject lost canonical address membership", input)
		}
	}
	if aliases := newSubjectAliasSet("fe80::7%en0"); len(aliases.addresses) != 0 {
		t.Fatal("zone-local text became an unscoped stored address")
	}
}
