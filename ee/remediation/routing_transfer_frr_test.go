// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

func TestFRRTransferPreviewRetainsTheOriginalPolicyAndOneExactPrefix(t *testing.T) {
	const config = `frr version 10.7.1
router bgp 64496
 neighbor 192.0.2.2 remote-as 64497
 neighbor 192.0.2.3 remote-as 64498
 address-family ipv4 unicast
  neighbor 192.0.2.2 route-map ORIGINAL in
  neighbor 192.0.2.3 route-map ORIGINAL in
 exit-address-family
!
route-map ORIGINAL deny 10
 match community REJECT
exit
route-map ORIGINAL permit 20
 set local-preference 125
exit
`
	peer := netip.MustParseAddr("192.0.2.2")
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	const peerASN = 64497
	got, err := draftFRRTransfer(t.Context(), config, peer, peerASN, prefix, 300, 65536)
	if err != nil || got.BeforeMap != "ORIGINAL" || got.AfterMap == "" || got.ExactPrefix != prefix.String() || got.CandidatePeer != peer.String() ||
		got.CandidateASN != peerASN || got.DefaultLocalPreference != 100 || got.WeightVerification {
		t.Fatalf("owned exact route preview was unavailable: %+v %v", got, err)
	}
	name := got.AfterMap
	want := []string{
		"ip prefix-list " + name + " seq 10 permit 203.0.113.0/24",
		"route-map " + name + " permit 10", "match ip address prefix-list " + name, "call ORIGINAL", "on-match next", "exit",
		"route-map " + name + " permit 20", "match ip address prefix-list " + name, "set local-preference 300", "exit",
		"route-map " + name + " permit 30", "call ORIGINAL", "exit",
		"router bgp 64496", "address-family ipv4 unicast", "neighbor 192.0.2.2 route-map " + name + " in", "exit-address-family", "exit",
	}
	rollback := []string{"router bgp 64496", "address-family ipv4 unicast", "neighbor 192.0.2.2 route-map ORIGINAL in", "exit-address-family", "exit", "no route-map " + name, "no ip prefix-list " + name}
	if !slices.Equal(got.Configure, want) || !slices.Equal(got.Withdraw, rollback) {
		t.Fatalf("dry run changed a shared policy, another route or its rollback: %+v", got)
	}
	weighted := strings.Replace(config, "router bgp 64496\n", "router bgp 64496\n bgp default local-preference 250\n neighbor 192.0.2.3 weight 10\n", 1)
	if got, err := draftFRRTransfer(t.Context(), weighted, peer, peerASN, prefix, 300, 65536); err != nil || !got.WeightVerification || got.DefaultLocalPreference != 250 {
		t.Fatalf("dry run lost the configured default preference or local weight verification: %+v %v", got, err)
	}
	var validation rem.Error
	if got, err := draftFRRTransfer(t.Context(), weighted, peer, peerASN, prefix, 250, 65536); !errors.As(err, &validation) || validation.Code != "validation" || len(got.Configure) != 0 {
		t.Fatalf("preference no higher than the router default was accepted: %+v %v", got, err)
	}
	if got, err := draftFRRTransfer(t.Context(), config, peer, peerASN+1, prefix, 300, 65536); !errors.As(err, &validation) || validation.Code != "validation" || len(got.Configure) != 0 {
		t.Fatalf("an archive for another upstream ASN produced commands: %+v %v", got, err)
	}
	grouped := strings.Replace(config, " neighbor 192.0.2.2 remote-as 64497\n", " neighbor TRANSIT peer-group\n neighbor TRANSIT remote-as 64497\n neighbor 192.0.2.2 peer-group TRANSIT\n", 1)
	if got, err := draftFRRTransfer(t.Context(), grouped, peer, peerASN, prefix, 300, 65536); err != nil || got.CandidateASN != peerASN ||
		!slices.Equal(got.Configure, want) || !slices.Equal(got.Withdraw, rollback) {
		t.Fatalf("an exact peer-group ASN failed to preserve the candidate attachment: %+v %v", got, err)
	}
	for label, value := range map[string]string{
		"unknown configuration format": strings.TrimPrefix(config, "frr version 10.7.1\n"),
		"namespace collision":          config + "\nroute-map " + name + " permit 70\n",
		"dangling policy reference":    config + "\nroute-map DIFFERENT permit 30\n call " + name + "\n",
		"prefix collision":             config + "\nip prefix-list " + name + " seq 70 permit 198.51.100.0/24\n",
		"conflicting peer attachment":  strings.Replace(config, "  neighbor 192.0.2.3 route-map ORIGINAL in", "  neighbor 192.0.2.2 route-map ORIGINAL in", 1),
		"ambiguous routing table":      strings.Replace(config, "router bgp 64496", "router bgp 64496 vrf CUSTOMER", 1),
		"unknown named policy":         strings.ReplaceAll(config, "route-map ORIGINAL permit", "route-map OTHER permit"),
		"unspecified remote ASN":       strings.Replace(config, "neighbor 192.0.2.2 remote-as 64497", "neighbor 192.0.2.2 remote-as external", 1),
		"remote ASN in wrong family":   strings.Replace(strings.Replace(config, " neighbor 192.0.2.2 remote-as 64497\n", "", 1), " address-family ipv4 unicast\n", " address-family ipv4 unicast\n  neighbor 192.0.2.2 remote-as 64497\n", 1),
		"conflicting peer-group ASN":   strings.Replace(grouped, " neighbor 192.0.2.2 peer-group TRANSIT\n", " neighbor 192.0.2.2 peer-group TRANSIT\n neighbor 192.0.2.2 remote-as 64498\n", 1),
	} {
		if label == "unknown named policy" {
			value = strings.ReplaceAll(value, "route-map ORIGINAL deny", "route-map OTHER deny")
		}
		if got, err := draftFRRTransfer(t.Context(), value, peer, peerASN, prefix, 300, 65536); !errors.Is(err, rem.ErrUnknownBlastRadius) || len(got.Configure) != 0 {
			t.Fatalf("%s produced a configuration: %+v %v", label, got, err)
		}
	}
}
