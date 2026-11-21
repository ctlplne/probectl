// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"encoding/hex"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

// DecodePhysicalPeerSession derives a bounded lifecycle fact from a complete
// frame. The caller binds its verified router/listener identities separately;
// no BMP header or fact selects a tenant, context, hand-off or carrier role.
func DecodePhysicalPeerSession(ctx context.Context, raw []byte, budget PeerMessageBudget) (*entity.BMPPeerSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) < bmpCommonHeaderLen {
		return nil, ErrBMPPeerDown
	}
	var header BMPRouteViewHeader
	out := &entity.BMPPeerSession{Version: 1}
	switch raw[5] {
	case bmpPeerUp:
		peer, _, err := physicalPeerOpenASNs(ctx, raw, budget)
		if err != nil {
			return nil, err
		}
		header, out.State = peer.Header, "up"
	case 2:
		peer, err := DecodePhysicalPeerDown(ctx, raw, budget)
		if err != nil {
			return nil, err
		}
		header, out.State = peer.Header, "down"
		reason := uint32(peer.Reason)
		out.DownReason = &reason
		if peer.Reason == 5 {
			out.State = "monitoring_withdrawn"
		}
		if peer.FSMEventKnown {
			value := uint32(peer.FSMEvent)
			out.FSMEvent = &value
		}
		if len(peer.Notification) != 0 {
			code, subcode := uint32(peer.Notification[19]), uint32(peer.Notification[20])
			out.NotificationCode, out.NotificationSubcode = &code, &subcode
		}
	default:
		return nil, ErrBMPPeerDown
	}
	out.PeerAddress, out.PeerASN, out.Flags = header.PeerAddress.Unmap().String(), header.PeerASN, uint32(header.Flags)
	out.RawFrame = append([]byte(nil), raw...)
	out.FrameDigest = hex.EncodeToString(crypto.Hash(raw))
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

// BMPNeighborTransition retains the protected protocol identity and typed
// reason. The existing physical evidence path retains the original bytes.
type BMPNeighborTransition struct {
	Peer                BMPObservationPeer `json:"peer"`
	State               string             `json:"state"`
	DownReason          *uint32            `json:"down_reason,omitempty"`
	FSMEvent            *uint32            `json:"fsm_event,omitempty"`
	NotificationCode    *uint32            `json:"notification_code,omitempty"`
	NotificationSubcode *uint32            `json:"notification_subcode,omitempty"`
	FrameDigest         string             `json:"frame_digest"`
}

// DecodeBMPNeighborTransition uses the physical session decoder's original
// validation and omits opaque OPEN or NOTIFICATION payloads.
func DecodeBMPNeighborTransition(ctx context.Context, raw []byte, budget PeerMessageBudget) (BMPNeighborTransition, error) {
	fact, err := DecodePhysicalPeerSession(ctx, raw, budget)
	if err != nil {
		return BMPNeighborTransition{}, err
	}
	header, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen : bmpCommonHeaderLen+bmpPeerHeaderLen])
	if err != nil {
		return BMPNeighborTransition{}, err
	}
	return BMPNeighborTransition{Peer: observeBMPPeer(header), State: fact.State, DownReason: fact.DownReason, FSMEvent: fact.FSMEvent,
		NotificationCode: fact.NotificationCode, NotificationSubcode: fact.NotificationSubcode, FrameDigest: fact.FrameDigest}, nil
}

// PhysicalPeerASNs describes the two complete original OPENs. Neither ASN
// selects canonical ownership or proves a forwarding path.
type PhysicalPeerASNs struct{ Local, Remote uint32 }

// PhysicalPeerOpenASNs derives both ASNs from a complete physical Peer Up.
// It never substitutes a Loc-RIB pseudo-peer, header-only ASN or Down frame.
func PhysicalPeerOpenASNs(ctx context.Context, raw []byte, budget PeerMessageBudget) (PhysicalPeerASNs, error) {
	_, asns, err := physicalPeerOpenASNs(ctx, raw, budget)
	return asns, err
}

func physicalPeerOpenASNs(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerUp, PhysicalPeerASNs, error) {
	peer, err := parseBMPPeerUp(ctx, raw, budget)
	if err != nil {
		return PeerUp{}, PhysicalPeerASNs{}, err
	}
	if !physicalPeerHeader(peer.Header) {
		return PeerUp{}, PhysicalPeerASNs{}, ErrBMPPeerUp
	}
	local, err := physicalOpenASN(peer.SentOpen)
	if err != nil {
		return PeerUp{}, PhysicalPeerASNs{}, err
	}
	remote, err := physicalOpenASN(peer.ReceivedOpen)
	if err != nil || remote != peer.Header.PeerASN {
		return PeerUp{}, PhysicalPeerASNs{}, ErrBMPPeerUp
	}
	if err := ctx.Err(); err != nil {
		return PeerUp{}, PhysicalPeerASNs{}, err
	}
	return peer, PhysicalPeerASNs{Local: local, Remote: remote}, nil
}

func physicalOpenASN(raw []byte) (uint32, error) {
	capabilities, err := parseRouteOpenCapabilities(raw)
	if err != nil {
		return 0, err
	}
	wire := uint32(binary.BigEndian.Uint16(raw[20:22]))
	asn := wire
	if capabilities.fourAS {
		asn = capabilities.asn
	}
	if asn == 0 || asn <= 65535 && wire != asn || asn > 65535 && wire != 23456 {
		return 0, ErrBMPPeerUp
	}
	return asn, nil
}
