// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestSNMPPrefixReceiverKeepsPresenceAndRefusesPartialTables(t *testing.T) {
	if rows, err := parseSNMPPrefixEvidence(nil); err != nil || rows != nil {
		t.Fatal("legacy prefix absence became a complete table", err)
	}
	one := &agentv1.SnmpInterfacePrefix{IfIndex: 7, Prefix: "192.0.2.0/24", OnLink: true}
	two := &agentv1.SnmpInterfacePrefix{IfIndex: 8, Prefix: "2001:db8::/32", OnLink: false}
	set := &agentv1.SnmpInterfacePrefixSnapshot{Prefixes: []*agentv1.SnmpInterfacePrefix{two, one}}
	rows, err := parseSNMPPrefixEvidence(set)
	if err != nil || len(rows) != 2 || rows[0].IfIndex != 7 || !rows[0].OnLink || rows[1].IfIndex != 8 || rows[1].OnLink {
		t.Fatal("receiver changed complete prefix fields/order", err)
	}
	one.Prefix = "198.51.100.0/24"
	if rows[0].Prefix.String() != "192.0.2.0/24" {
		t.Fatal("wire input mutated owned prefix metadata")
	}
	for _, bad := range []*agentv1.SnmpInterfacePrefixSnapshot{{},
		{Prefixes: []*agentv1.SnmpInterfacePrefix{one, nil}},
		{Prefixes: []*agentv1.SnmpInterfacePrefix{one, one}},
		{Prefixes: []*agentv1.SnmpInterfacePrefix{one, {IfIndex: 9, Prefix: "router.example"}}},
		{Prefixes: []*agentv1.SnmpInterfacePrefix{one, {IfIndex: 9, Prefix: "192.0.2.1/24"}}},
	} {
		if got, err := parseSNMPPrefixEvidence(bad); err == nil || got != nil {
			t.Fatal("late malformed/incomplete prefix table published partial metadata")
		}
	}
}
