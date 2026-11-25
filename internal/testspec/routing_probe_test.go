// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"maps"
	"testing"
)

func TestRoutingProbeDefinitionRequiresCompleteCanonicalHandoff(t *testing.T) {
	params := map[string]string{
		RoutingProbeHandoffParam:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		RoutingProbePeerParam:      "192.0.2.1",
		RoutingProbeInterfaceParam: "eth1.20",
		RoutingProbeSourceParam:    "192.0.2.20",
		RoutingProbePeerMACParam:   "02:01:02:03:04:05",
	}
	const destination = "203.0.113.90"
	got, err := ParseRoutingProbeBinding("icmp", destination, params)
	if err != nil || got == nil || got.HandoffID != params[RoutingProbeHandoffParam] ||
		got.Peer.String() != params[RoutingProbePeerParam] || got.Egress.Source != params[RoutingProbeSourceParam] {
		t.Fatalf("valid binding did not preserve exact parameters: %v, %v", got, err)
	}
	if legacy, err := ParseRoutingProbeBinding("icmp", "example.com", map[string]string{"count": "3"}); err != nil || legacy != nil {
		t.Fatalf("ordinary test acquired routing probe authority: %v, %v", legacy, err)
	}
	for key := range params {
		missing := maps.Clone(params)
		delete(missing, key)
		if _, err := ParseRoutingProbeBinding("icmp", destination, missing); err == nil {
			t.Fatalf("partial binding without %s was accepted", key)
		}
	}
	if _, err := ParseRoutingProbeBinding("tcp", destination, params); err == nil {
		t.Fatal("non-ICMP test acquired routing probe authority")
	}
	if _, err := ParseRoutingProbeBinding("icmp", "example.com", params); err == nil {
		t.Fatal("hostname acquired routing probe authority")
	}
	params[RoutingProbePeerParam] = params[RoutingProbeSourceParam]
	if _, err := ParseRoutingProbeBinding("icmp", destination, params); err == nil {
		t.Fatal("probe source was treated as a distinct upstream peer")
	}
}
