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

func TestSNMPPrefixSnapshotKeepsCompleteOwnedCanonicalRows(t *testing.T) {
	if got, err := NormalizeSNMPInterfacePrefixes(nil); err != nil || got != nil {
		t.Fatal("legacy prefix absence became usable data", err)
	}
	input := []SNMPInterfacePrefix{{IfIndex: 2147483647, Prefix: netip.MustParsePrefix("2001:db8::/32")},
		{IfIndex: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), OnLink: true},
		{IfIndex: 1, Prefix: netip.MustParsePrefix("0.0.0.0/0")}}
	got, err := NormalizeSNMPInterfacePrefixes(input)
	if err != nil || len(got) != len(input) || got[0].Prefix.String() != "0.0.0.0/0" || got[1] != input[1] || got[2] != input[0] {
		t.Fatal("complete prefix metadata lost ordered rows, protocol bounds or truth", err)
	}
	input[1].Prefix = netip.MustParsePrefix("198.51.100.0/24")
	if got[1].Prefix.String() != "192.0.2.0/24" {
		t.Fatal("caller mutated the normalized complete prefix set")
	}
	if again, err := NormalizeSNMPInterfacePrefixes([]SNMPInterfacePrefix{got[2], got[1], got[0]}); err != nil || !slices.Equal(again, got) {
		t.Fatal("equivalent whole-set order changed replay identity", err)
	}
}

func TestSNMPPrefixSnapshotRejectsPartialMalformedAndForeignClaims(t *testing.T) {
	row := SNMPInterfacePrefix{IfIndex: 7, Prefix: netip.MustParsePrefix("192.0.2.0/24"), OnLink: true}
	for _, input := range [][]SNMPInterfacePrefix{{}, {row, row}, {{IfIndex: 0, Prefix: row.Prefix}},
		{{IfIndex: 2147483648, Prefix: row.Prefix}}, {{IfIndex: 7}},
		{{IfIndex: 7, Prefix: netip.MustParsePrefix("192.0.2.1/24")}},
		{{IfIndex: 7, Prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120")}}} {
		if got, err := NormalizeSNMPInterfacePrefixes(input); err == nil || got != nil {
			t.Fatal("invalid or incomplete prefix table became a usable partial set")
		}
	}
	now := time.Now()
	claim := Observation{ID: "33333333-3333-4333-8333-333333333333",
		Source: SourceKey{AgentID: "agent", Kind: DeviceTarget, SourceRef: "192.0.2.1"},
		Alias:  AliasKey{Kind: AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: now,
		SNMPInterfacePrefixes: []SNMPInterfacePrefix{row}}
	if _, err := claim.Normalize(now); err != nil {
		t.Fatal("configured target lost complete prefix metadata", err)
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Source.Kind = FlowExporter },
		func(o *Observation) { o.Alias.Kind, o.Alias.Value = SNMPInterfaceAlias, "7" },
		func(o *Observation) { o.SourceRef = "snmp:ifIndex:7" },
	} {
		bad := claim
		change(&bad)
		if _, err := bad.Normalize(now); err == nil {
			t.Fatal("prefix table escaped its exact configured device claim")
		}
	}
}

func TestSNMPPrefixSnapshotAdmissionNeverTruncatesToFit(t *testing.T) {
	var rows []SNMPInterfacePrefix
	for i := uint32(1); i <= 70000; i++ {
		rows = append(rows, SNMPInterfacePrefix{IfIndex: i, Prefix: netip.MustParsePrefix("2001:db8::/32"), OnLink: true})
	}
	if got, err := NormalizeSNMPInterfacePrefixes(rows); err == nil || got != nil {
		t.Fatal("oversized complete prefix table was truncated or admitted")
	}
}
