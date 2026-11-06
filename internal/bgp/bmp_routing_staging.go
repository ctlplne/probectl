// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

const bmpPeerUp = 3

type bmpRoutingStager interface {
	StageRoutingPeer(context.Context, *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error)
}

// The decoder already checked the six common-header bytes before returning
// payload. Reproduce those exact validated fields; retain every original body
// byte. The router identity and serial come only from the admitted mTLS session.
func (l *BMPListener) queueRoutingPeerUp(id bmpIdentity, session uint64, payload []byte) error {
	if _, ok := l.evidence.(bmpRoutingStager); !ok || len(payload) == 0 || payload[0] != 3 {
		return nil
	}
	if len(payload) < bmpPeerHeaderLen {
		return ErrBMPPeerUp
	}
	header, err := ParseBMPRouteViewHeader(payload[:bmpPeerHeaderLen])
	if err != nil {
		return err
	}
	if header.Distinguisher != ([8]byte{}) {
		return nil
	} // explicit binding remains required
	nonce, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	raw := make([]byte, bmpCommonHeaderLen+len(payload))
	raw[0], raw[5] = bmpVersion, bmpPeerUp
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[6:], payload)
	observed := l.now().UTC()
	request := &agentv1.BmpRoutingPeerUp{ObservationId: nonce, ConfiguredRef: id.AgentID, OriginSerial: id.Serial, ObservedUnixNanos: observed.UnixNano(), Message: raw}
	if !l.queuePeerEvidence(bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial, sessionHandle: session, observedAt: observed, routingPeerUp: request}) {
		return errors.New("bgp: complete routing evidence queue admission exceeded")
	}
	return nil
}

func (l *BMPListener) stageRoutingEvidence(ctx context.Context, peer bmpPeerEvidence) {
	stager, ok := l.evidence.(bmpRoutingStager)
	if !ok || peer.tenantID != l.laneTenant || peer.routingPeerUp == nil {
		return
	}
	if _, err := stager.StageRoutingPeer(ctx, peer.routingPeerUp); err != nil {
		l.log.Warn("bmp routing source staging unavailable", "tenant_id", peer.tenantID, "agent_id", l.evidenceAgent, "error", err)
	}
}
