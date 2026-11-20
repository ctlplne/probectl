// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strconv"

	"github.com/ctlplne/probectl/internal/remediation"
)

// flowSpecDecisionFromRetainedRow uses the normalized IP transport field.
// In the flow query, "protocol" identifies the export format, such as IPFIX.
// The retained integer fields cannot distinguish an absent port from zero.
func flowSpecDecisionFromRetainedRow(match remediation.FlowSpecTransport, group map[string]string) remediation.FlowSpecTransportMatch {
	transport := group["transport"]
	switch transport {
	case "tcp", "udp", "icmp":
	case "6":
		transport = "tcp"
	case "17":
		transport = "udp"
	default:
		number, err := strconv.ParseUint(transport, 10, 8)
		if err != nil || number == 0 {
			transport = ""
		}
	}
	return match.MatchObservation(transport, retainedNonzeroPort(group["src_port"]), retainedNonzeroPort(group["dst_port"]))
}

func retainedNonzeroPort(value string) *uint16 {
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil || number == 0 {
		return nil
	}
	port := uint16(number)
	return &port
}
