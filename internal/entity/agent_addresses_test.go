// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestAgentAddressSnapshotsKeepPresenceAndCompleteCanonicalHostFacts(t *testing.T) {
	legacy, err := NormalizeAgentAddresses(nil)
	if err != nil || legacy != nil {
		t.Fatal("legacy absence changed")
	}
	clear, err := ParseAgentAddressSnapshot(nil)
	if err != nil || clear == nil || len(clear) != 0 {
		t.Fatal("present empty snapshot lost its clear")
	}
	input := []string{"2001:db8::1", "::ffff:10.2.0.7", "10.2.0.7", "127.0.0.1", "::1", "fe80::1", "fd00::1"}
	got, err := ParseAgentAddressSnapshot(input)
	if err != nil || len(got) != 6 || !slices.Contains(got, netip.MustParseAddr("10.2.0.7")) || !slices.Contains(got, netip.MustParseAddr("fe80::1")) {
		t.Fatal("canonical host set lost admitted local addresses")
	}
	for _, value := range []string{"", "host.example", "10.2.0.7/24", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "fe80::1%eth0", "::ffff:10.2.0.7%eth0"} {
		if _, err := ParseAgentAddressSnapshot([]string{value}); err == nil {
			t.Fatalf("non-host/invalid address admitted: %q", value)
		}
	}
	if _, err := NormalizeAgentAddresses([]netip.Addr{{}}); err == nil {
		t.Fatal("invalid typed address admitted")
	}
	addresses := make([]netip.Addr, MaxAgentAddressSnapshotBytes/4)
	for i := range addresses {
		addresses[i] = netip.MustParseAddr("::1")
	}
	if _, err := NormalizeAgentAddresses(addresses); err == nil {
		t.Fatal("oversize complete input was deduplicated into an accepted partial budget")
	}
}

func TestAgentAddressMetadataRequiresTheExactSiteClaimAndClonesInput(t *testing.T) {
	now := time.Now().UTC()
	input := Observation{ID: "33333333-3333-4333-8333-333333333333", Source: SourceKey{AgentID: "agent", Kind: AgentSite, SourceRef: "agent"}, Alias: AliasKey{Kind: AgentSiteAlias, Value: "dub-1"}, SourceRef: "agent:label:site", ObservedAt: now, AgentAddresses: []netip.Addr{netip.MustParseAddr("10.2.0.7")}}
	normalized, err := input.Normalize(now)
	if err != nil {
		t.Fatal(err)
	}
	input.AgentAddresses[0] = netip.MustParseAddr("10.9.0.1")
	if normalized.AgentAddresses[0].String() != "10.2.0.7" {
		t.Fatal("caller mutated normalized facts")
	}
	input.Source = SourceKey{AgentID: "agent", Kind: DeviceTarget, SourceRef: "10.2.0.7"}
	input.Alias = AliasKey{Kind: AddressAlias, Value: "10.2.0.7"}
	input.SourceRef = "snmp:configured-target"
	for _, values := range [][]netip.Addr{normalized.AgentAddresses, {}} {
		input.AgentAddresses = values
		if _, err := input.Normalize(now); err == nil {
			t.Fatal("another source family attached agent address metadata")
		}
	}
}
