//go:build integration

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"errors"
	"net/netip"
	"testing"
)

// This extends the required real provider component. Facts here exercise the
// source adapter; owned local authority/native release proof is separate.
func liveNetBoxSubjectProof(t *testing.T, resolver *Resolver, tenants, ips, prefixes, ipv6 map[string]string) {
	t.Helper()
	callers := map[string]string{"a": netBoxTenantA, "b": netBoxTenantB}
	for _, lane := range []string{"a", "b"} {
		ctx := netBoxContext(callers[lane])
		if prefixes[lane] == "" || ipv6[lane] == "" {
			t.Fatal("required real prefix fixture is absent")
		}
		facts := NetBoxTagFacts{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
		selected, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", ips[lane])
		if err != nil || selected.Candidate().Value != "role-"+lane || !selected.Matches(facts) {
			t.Fatalf("lane %s exact IP-source correspondence: %v", lane, err)
		}
		if fresh, err := resolver.RecheckNetBoxSubjectTag(ctx, facts, selected.Candidate()); err != nil || fresh.Candidate() != selected.Candidate() {
			t.Fatal("fresh exact IP CI did not preserve review")
		}
		for _, row := range []struct{ network, id string }{{"192.0.2.0/24", prefixes[lane]}, {"2001:db8::/32", ipv6[lane]}} {
			facts := NetBoxTagFacts{Prefix: netip.MustParsePrefix(row.network)}
			if row.network == "192.0.2.0/24" && lane == "a" {
				if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", ""); !errors.Is(err, ErrNoTagCandidate) {
					t.Fatal("real overlapping VRFs silently selected a prefix")
				}
			} else if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", ""); err != nil {
				t.Fatal("unambiguous tenant prefix did not auto-resolve")
			}
			for _, field := range []string{"role", "site"} {
				want := "site-" + lane
				if field == "role" {
					want = "ipam-role-" + lane
				}
				selected, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, field, row.id)
				if err != nil || selected.Candidate().NetBoxTenantID != tenants[lane] ||
					selected.Candidate().LookupCIID != "netbox:ipam.prefix:"+row.id || selected.Candidate().CIID != selected.Candidate().LookupCIID ||
					selected.Candidate().Value != want || !selected.Matches(facts) {
					t.Fatalf("lane %s real prefix %s %s: %v", lane, row.network, field, err)
				}
				if fresh, err := resolver.RecheckNetBoxSubjectTag(ctx, facts, selected.Candidate()); err != nil || fresh.Candidate() != selected.Candidate() {
					t.Fatal("unchanged real prefix could not be re-attested")
				}
			}
			other := "a"
			if lane == "a" {
				other = "b"
			}
			if _, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "role", prefixes[other]); err == nil {
				t.Fatal("foreign exact source ID selected another mapped tenant's prefix")
			}
		}
	}
	ctx := netBoxContext(netBoxTenantA)
	facts := NetBoxTagFacts{Prefix: netip.MustParsePrefix("192.0.2.0/24")}
	before, err := resolver.PreviewNetBoxSubjectTag(ctx, facts, "site", prefixes["a"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { liveNetBoxMutation(t, "prefix-vrf", "a", "original") })
	liveNetBoxMutation(t, "prefix-vrf", "a", "next")
	after, err := resolver.RecheckNetBoxSubjectTag(ctx, facts, before.Candidate())
	if err != nil || after.Candidate().Value != before.Candidate().Value || after.Candidate().CIID != before.Candidate().CIID ||
		after.Candidate().SourceRef == before.Candidate().SourceRef {
		t.Fatal("actual same-value VRF move preserved stale reviewed source provenance")
	}
	liveNetBoxMutation(t, "prefix-vrf", "a", "original")
}
