// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/remediation"
)

func TestFlowSpecRetainedTransportDoesNotConfuseExportFormatOrMissingPort(t *testing.T) {
	port := uint16(1443)
	match := remediation.FlowSpecTransport{Protocol: "udp", DestinationPort: &port}
	for _, tc := range []struct {
		name  string
		group map[string]string
		want  remediation.FlowSpecTransportMatch
	}{
		{"ipfix observation", map[string]string{"protocol": "ipfix", "transport": "udp", "dst_port": "1443"}, remediation.FlowSpecTransportInside},
		{"canonical number", map[string]string{"transport": "17", "dst_port": "1443"}, remediation.FlowSpecTransportInside},
		{"other IP transport", map[string]string{"transport": "47"}, remediation.FlowSpecTransportOutside},
		{"format is not transport", map[string]string{"protocol": "udp", "dst_port": "1443"}, remediation.FlowSpecTransportUnknown},
		{"unidentified transport", map[string]string{"transport": "0", "dst_port": "1443"}, remediation.FlowSpecTransportUnknown},
		{"ambiguous zero port", map[string]string{"transport": "udp", "dst_port": "0"}, remediation.FlowSpecTransportUnknown},
		{"overflowing port", map[string]string{"transport": "udp", "dst_port": "65536"}, remediation.FlowSpecTransportUnknown},
		{"known mismatch", map[string]string{"transport": "udp", "dst_port": "2443"}, remediation.FlowSpecTransportOutside},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowSpecDecisionFromRetainedRow(match, tc.group); got != tc.want {
				t.Fatalf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}
