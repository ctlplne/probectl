// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"errors"
	"net/netip"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
)

const (
	RoutingProbeHandoffParam   = "routing_probe_handoff_id"
	RoutingProbePeerParam      = "routing_probe_peer_address"
	RoutingProbeInterfaceParam = "routing_probe_interface"
	RoutingProbeSourceParam    = "routing_probe_source_address"
	RoutingProbePeerMACParam   = "routing_probe_peer_mac"
)

// RoutingProbeBinding is the operator's expected link for a registered test.
// Its params are part of the current signed executable definition and digest.
// The control plane must still resolve the handoff and peer within its current
// tenant snapshot. The probe agent independently pins the local coordinates.
type RoutingProbeBinding struct {
	HandoffID string
	Peer      netip.Addr
	Egress    entity.ICMPEgressWitness
}

// ParseRoutingProbeBinding leaves existing, ordinary tests without a binding.
// The presence of any reserved key requires the complete routing probe setup.
func ParseRoutingProbeBinding(kind, literal string, params map[string]string) (*RoutingProbeBinding, error) {
	present := false
	for _, key := range [...]string{RoutingProbeHandoffParam, RoutingProbePeerParam, RoutingProbeInterfaceParam, RoutingProbeSourceParam, RoutingProbePeerMACParam} {
		if _, set := params[key]; set {
			present = true
			break
		}
	}
	if !present {
		return nil, nil
	}
	target, targetErr := netip.ParseAddr(literal)
	peer, peerErr := netip.ParseAddr(params[RoutingProbePeerParam])
	id, idErr := uuid.Parse(params[RoutingProbeHandoffParam])
	egress := entity.ICMPEgressWitness{Interface: params[RoutingProbeInterfaceParam],
		Source: params[RoutingProbeSourceParam], PeerMAC: params[RoutingProbePeerMACParam]}
	if kind != "icmp" || targetErr != nil || target.String() != literal || idErr != nil || id == uuid.Nil ||
		id.String() != params[RoutingProbeHandoffParam] || peerErr != nil || peer.String() != params[RoutingProbePeerParam] ||
		!peer.IsGlobalUnicast() || peer.Is4In6() || peer.Zone() != "" ||
		peer == target || peer.String() == egress.Source || !egress.ValidCoordinates(target) {
		return nil, errors.New("routing probe requires canonical ICMP target, handoff UUID, peer address, interface, source address and peer MAC")
	}
	return &RoutingProbeBinding{HandoffID: id.String(), Peer: peer, Egress: egress}, nil
}
