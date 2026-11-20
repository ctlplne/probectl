// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import "testing"

func TestFlowSpecTransportPreservesMissingObservationCoverage(t *testing.T) {
	one, two, other := uint16(1053), uint16(1443), uint16(2443)
	selected := FlowSpecTransport{Protocol: "udp", SourcePort: &one, DestinationPort: &two}
	if err := selected.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                string
		protocol            string
		source, destination *uint16
		want                FlowSpecTransportMatch
	}{
		{"exact", "udp", &one, &two, FlowSpecTransportInside},
		{"wrong protocol", "tcp", nil, nil, FlowSpecTransportOutside},
		{"wrong destination", "udp", nil, &other, FlowSpecTransportOutside},
		{"wrong source", "udp", &other, nil, FlowSpecTransportOutside},
		{"missing source", "udp", nil, &two, FlowSpecTransportUnknown},
		{"missing destination", "udp", &one, nil, FlowSpecTransportUnknown},
		{"missing transport", "", &one, &two, FlowSpecTransportUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selected.MatchObservation(tc.protocol, tc.source, tc.destination); got != tc.want {
				t.Fatalf("match decision = %v, want %v", got, tc.want)
			}
		})
	}
	if got := (FlowSpecTransport{Protocol: "tcp"}).MatchObservation("tcp", nil, nil); got != FlowSpecTransportInside {
		t.Fatalf("protocol-only proposal required unselected port evidence: %v", got)
	}
	if err := (FlowSpecTransport{Protocol: "arbitrary"}).Validate(); err == nil {
		t.Fatal("an unsupported protocol entered the proposal")
	}
	portZero := uint16(0)
	if err := (FlowSpecTransport{Protocol: "tcp", DestinationPort: &portZero}).Validate(); err == nil {
		t.Fatal("an indistinguishable retained port entered the proposal")
	}
}
