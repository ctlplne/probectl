// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"

	"github.com/ctlplne/probectl/internal/entity"
)

// Peer identity is independent of route UPDATE decoding. A complete physical
// Peer Up attests the address/ASN observed by this admitted router; it says
// nothing about forwarding, selected routes or continuing session health.
func (l *BMPListener) queuePhysicalPeerUpEvidence(ctx context.Context, id bmpIdentity, session uint64, payload []byte) error {
	if l.evidence == nil {
		return nil
	}
	if id.TenantID != l.laneTenant || id.AgentID == "" || id.Serial == "" || session == 0 {
		return entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(payload) < bmpPeerHeaderLen {
		return ErrBMPPeerUp
	}
	// Non-global views need their own operator-bound context. A fabricated
	// Loc-RIB peer is not a physical neighbour; retain its separate staging.
	if payload[0] != 0 {
		return nil
	}
	size := int64(len(payload)) + bmpCommonHeaderLen
	if size > l.routingStateBytes/128 {
		return ErrBMPPeerUpBudget
	}
	raw := make([]byte, bmpCommonHeaderLen+len(payload))
	raw[0], raw[5] = bmpVersion, bmpPeerUp
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[bmpCommonHeaderLen:], payload)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !l.queuePeerEvidence(bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial, sessionHandle: session, physicalPeerUp: raw, observedAt: l.now().UTC()}) {
		return ErrBMPPeerUpBudget
	}
	return nil
}

// Whole metadata validation runs only in the existing single evidence worker,
// never in each concurrent socket reader. No partially decoded peer is returned.
func (l *BMPListener) physicalPeerUpEvidence(ctx context.Context, pending bmpPeerEvidence) (bmpPeerEvidence, error) {
	none := bmpPeerEvidence{}
	if pending.tenantID != l.laneTenant || pending.routerAgentID == "" || pending.routerSerial == "" || pending.sessionHandle == 0 || pending.observedAt.IsZero() {
		return none, entity.ErrScopeMismatch
	}
	peer, err := parseBMPPeerUp(ctx, pending.physicalPeerUp, PeerMessageBudget{MemoryBytes: l.routingStateBytes, WorkUnits: l.routingStateBytes})
	if err != nil {
		return none, err
	}
	header := peer.Header
	if header.PeerType != 0 || header.Flags&^byte(0xf0) != 0 || header.PeerASN == 0 || !header.PeerAddress.IsValid() || header.PeerAddress.IsUnspecified() || header.PeerAddress.IsMulticast() {
		return none, ErrBMPPeerUp
	}
	remote, err := parseRouteOpenCapabilities(peer.ReceivedOpen)
	if err != nil {
		return none, err
	}
	asn := uint32(binary.BigEndian.Uint16(peer.ReceivedOpen[20:22]))
	if remote.fourAS {
		asn = remote.asn
	}
	if asn == 0 || asn != header.PeerASN {
		return none, ErrBMPPeerUp
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return bmpPeerEvidence{tenantID: pending.tenantID, routerAgentID: pending.routerAgentID, routerSerial: pending.routerSerial, sessionHandle: pending.sessionHandle,
		peerAddress: header.PeerAddress.String(), peerASN: asn, observedAt: pending.observedAt}, nil
}
