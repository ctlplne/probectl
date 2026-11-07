// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net/netip"
	"testing"
)

func TestFlowCaptureKeyBindsTenantCertifiedSenderTupleAndEveryDigestByte(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	input := FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	raw := [32]byte{1, 2, 3}
	first, err := FlowCaptureKey(tenant, "source-a", raw, input)
	if err != nil || first == ([32]byte{}) {
		t.Fatal("complete capture tuple was refused", err)
	}
	if got, err := FlowCaptureKey(tenant, "source-a", raw, input); err != nil || got != first {
		t.Fatal("identical witnessed observation changed its key", err)
	}
	for _, change := range []func(*FlowCaptureInput){
		func(v *FlowCaptureInput) { v.Exporter = netip.MustParseAddr("192.0.2.2") },
		func(v *FlowCaptureInput) { v.Source = netip.MustParseAddr("203.0.113.2") },
		func(v *FlowCaptureInput) { v.Destination = netip.MustParseAddr("2001:db8::2") },
		func(v *FlowCaptureInput) { v.Protocol = "netflow5" },
		func(v *FlowCaptureInput) { v.Domain = 0 },
	} {
		changed := input
		change(&changed)
		if got, err := FlowCaptureKey(tenant, "source-a", raw, changed); err != nil || got == first {
			t.Fatal("different routing tuple reused a capture witness", err)
		}
	}
	for i := range raw {
		changed := raw
		changed[i] ^= 0xff
		if got, err := FlowCaptureKey(tenant, "source-a", changed, input); err != nil || got == first {
			t.Fatal("raw flow digest lost a witnessed byte", i, err)
		}
	}
	for _, pair := range [][2]string{{tenant, "source-b"}, {"22222222-2222-4222-8222-222222222222", "source-a"}} {
		if got, err := FlowCaptureKey(pair[0], pair[1], raw, input); err != nil || got == first {
			t.Fatal("capture witness crossed tenant or authenticated sender", err)
		}
	}
	mapped := input
	mapped.Exporter = netip.MustParseAddr("::ffff:192.0.2.1")
	if got, err := FlowCaptureKey(tenant, "source-a", raw, mapped); err != nil || got != first {
		t.Fatal("routing tuple lost canonical address association", err)
	}
}

func TestFlowCaptureKeyRefusesMissingSenderMalformedScopeAndUnscopedAddresses(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	input := FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix"}
	for _, pair := range [][2]string{{tenant, ""}, {"bad-tenant", "source"}, {"00000000-0000-0000-0000-000000000000", "source"}} {
		if got, err := FlowCaptureKey(pair[0], pair[1], [32]byte{1}, input); err == nil || got != ([32]byte{}) {
			t.Fatal("unscoped witness created an identifier", err)
		}
	}
	for _, change := range []func(*FlowCaptureInput){
		func(v *FlowCaptureInput) { v.Exporter = netip.Addr{} },
		func(v *FlowCaptureInput) { v.Exporter = netip.MustParseAddr("224.0.0.1") },
		func(v *FlowCaptureInput) { v.Source = netip.MustParseAddr("fe80::1%other-interface") },
		func(v *FlowCaptureInput) { v.Protocol = "unknown" },
	} {
		changed := input
		change(&changed)
		if got, err := FlowCaptureKey(tenant, "source", [32]byte{1}, changed); err == nil || got != ([32]byte{}) {
			t.Fatal("invalid capture tuple created an identifier", err)
		}
	}
	if got, err := FlowCaptureKey(tenant, "source", [32]byte{}, input); err == nil || got != ([32]byte{}) {
		t.Fatal("missing opaque digest created a witness", err)
	}
}
