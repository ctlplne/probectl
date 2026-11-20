// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

// FlowSpecTransport is the exact transport portion of an inert FlowSpec
// proposal. The control plane resolves the destination from the owned
// protected entity in the cited finding. Optional ports match exact values.
type FlowSpecTransport struct {
	Protocol        string  `json:"protocol"`
	SourcePort      *uint16 `json:"source_port,omitempty"`
	DestinationPort *uint16 `json:"destination_port,omitempty"`
}

// FlowSpecTransportMatch keeps missing telemetry distinct from traffic that
// falls outside the proposed match.
type FlowSpecTransportMatch uint8

const (
	FlowSpecTransportUnknown FlowSpecTransportMatch = iota
	FlowSpecTransportOutside
	FlowSpecTransportInside
)

func (match FlowSpecTransport) Validate() error {
	if match.Protocol != "tcp" && match.Protocol != "udp" {
		return Error{Code: "validation", Message: "select a supported transport for the FlowSpec proposal"}
	}
	if (match.SourcePort != nil && *match.SourcePort == 0) ||
		(match.DestinationPort != nil && *match.DestinationPort == 0) {
		return Error{Code: "validation", Message: "port zero does not have measurable retained coverage"}
	}
	return nil
}

// MatchObservation evaluates only facts available on the retained row. An
// empty protocol or nil observed port represents unavailable evidence. A
// known condition outside the match establishes an outside result even if
// another field is missing.
func (match FlowSpecTransport) MatchObservation(protocol string, source, destination *uint16) FlowSpecTransportMatch {
	if protocol == "" {
		return FlowSpecTransportUnknown
	}
	if protocol != match.Protocol {
		return FlowSpecTransportOutside
	}
	if portDiffers(match.SourcePort, source) || portDiffers(match.DestinationPort, destination) {
		return FlowSpecTransportOutside
	}
	if (match.SourcePort != nil && source == nil) || (match.DestinationPort != nil && destination == nil) {
		return FlowSpecTransportUnknown
	}
	return FlowSpecTransportInside
}

func portDiffers(expected, observed *uint16) bool {
	return expected != nil && observed != nil && *expected != *observed
}
