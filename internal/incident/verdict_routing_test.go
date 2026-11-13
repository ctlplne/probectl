// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"strings"
	"testing"
)

func TestVerdictRoutingReferenceKeepsNamespaceAndRefusesMixedAuthority(t *testing.T) {
	fixture := func() VerdictCitation {
		return VerdictCitation{SourceKind: "router_bgp", Digest: strings.Repeat("a", 64), AgentID: "router-listener", Routing: &VerdictRoutingReference{ViewID: "aee337be-624f-440c-9be9-be3e2c19f7c5", GenerationID: "bc646676-f577-4818-8b9a-59f9fa9f71ad", Sequence: "9223372036854775807", Prefix: "2001:db8::/64", Address: "2001:db8::7", OriginASN: 4294967295}}
	}
	value := fixture()
	if key, err := value.SourceReference(); err != nil || key == "" {
		t.Fatal("complete original routing view refused", err)
	}
	key, _ := value.SourceReference()
	value.Routing.Address, value.Routing.Prefix, value.Routing.AddressesRedacted = "", "", true
	if redacted, err := value.SourceReference(); err != nil || redacted != key {
		t.Fatal("redaction changed original routing namespace", err)
	}

	for _, mutate := range []func(*VerdictCitation){
		func(c *VerdictCitation) { c.SourceKind = "entity_evidence"; c.EvidenceID = "original" },
		func(c *VerdictCitation) { c.EvidenceID = "original" },
		func(c *VerdictCitation) { c.PathRoundID = "01234567890123456789abcdefabcdef" },
		func(c *VerdictCitation) { c.PeerASN = 1; c.HandoffInterfaceID = c.Routing.ViewID },
		func(c *VerdictCitation) { c.Routing.ViewID = "not-an-original-view" },
		func(c *VerdictCitation) { c.Routing.Sequence = "0" },
		func(c *VerdictCitation) { c.Routing.Prefix = "::/0" },
		func(c *VerdictCitation) { c.Routing.Address = "2001:db9::7" },
		func(c *VerdictCitation) { c.Routing.OriginASN = 0 },
		func(c *VerdictCitation) { c.Routing.AddressesRedacted = true },
		func(c *VerdictCitation) { c.Digest = "" },
	} {
		value := fixture()
		mutate(&value)
		if _, err := value.SourceReference(); err == nil {
			t.Fatal("mixed, incomplete or malformed routing context acquired original authority")
		}
	}
}
