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
		peer, err := parseBMPPeerUp(ctx, raw, budget)
		if err != nil {
			return nil, err
		}
		if !physicalPeerHeader(peer.Header) {
			return nil, ErrBMPPeerUp
		}
		remote, err := parseRouteOpenCapabilities(peer.ReceivedOpen)
		if err != nil {
			return nil, err
		}
		asn := uint32(binary.BigEndian.Uint16(peer.ReceivedOpen[20:22]))
		if remote.fourAS {
			asn = remote.asn
		}
		if asn == 0 || asn != peer.Header.PeerASN {
			return nil, ErrBMPPeerUp
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
