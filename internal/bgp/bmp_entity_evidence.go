// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type bmpPeerEvidence struct {
	routingPeerUp *agentv1.BmpRoutingPeerUp // owned raw metadata, separate from peer-claim suppression
	sessionHandle uint64                    // listener-owned admitted session, never a BMP payload field
	tenantID      string
	routerAgentID string // from a verified router SVID, not the BMP frame
	routerSerial  string // exact verified SVID; revocation retires this evidence
	peerAddress   string
	peerASN       uint32
	observedAt    time.Time
}

type bmpPeerEvidenceKey struct {
	sessionHandle uint64
	routerAgentID string
	routerSerial  string
	peerAddress   string
	peerASN       uint32
}

const (
	bmpEvidenceRefresh         = 12 * time.Hour
	bmpEvidenceUnresolvedRetry = time.Hour
	bmpEvidenceRetry           = time.Minute
	bmpEvidenceMaxLag          = 11 * time.Hour
)

type bmpEvidenceAttempt struct {
	acceptedAt time.Time
	partialAt  time.Time
	attemptAt  time.Time
}

// RefreshEvidenceAfterRotation makes the next verified peer route restate its
// identity under the listener's new evidence certificate.
func (l *BMPListener) RefreshEvidenceAfterRotation() {
	if l == nil || l.evidenceReset == nil {
		return
	}
	select {
	case l.evidenceReset <- struct{}{}:
	default:
	}
}

func (state bmpEvidenceAttempt) due(now time.Time) bool {
	return (state.acceptedAt.IsZero() || !now.Before(state.acceptedAt.Add(bmpEvidenceRefresh))) &&
		(state.partialAt.IsZero() || !now.Before(state.partialAt.Add(bmpEvidenceUnresolvedRetry))) &&
		(state.attemptAt.IsZero() || !now.Before(state.attemptAt.Add(bmpEvidenceRetry)))
}

func (l *BMPListener) queuePeerEvidence(peer bmpPeerEvidence) {
	if l.evidence == nil || peer.tenantID != l.laneTenant {
		return
	}
	select {
	case l.evidenceQueue <- peer:
	default:
		drops := l.evidenceDrops.Add(1)
		if counter, ok := l.evidence.(interface{ QueueDrop() }); ok {
			counter.QueueDrop()
		}
		if drops&(drops-1) == 0 {
			l.log.Warn("bmp canonical evidence queue full; raw route event retained",
				"tenant_id", l.laneTenant, "agent_id", l.evidenceAgent,
				"dropped_batches", drops)
		}
	}
}

// One worker and a bounded queue keep the BMP socket read/publish path
// independent of a slow evidence service. The TTL map has an explicit ceiling
// even if a compromised router varies peer headers at high rate. A newly
// authenticated session must restate live peers under current assignments; the
// same certificate on an earlier connection is not a reusable evidence epoch.
func (l *BMPListener) evidenceLoop(ctx context.Context) {
	lastSent := make(map[bmpPeerEvidenceKey]bmpEvidenceAttempt)
	remember := func(key bmpPeerEvidenceKey, state bmpEvidenceAttempt) {
		lastSent[key] = state
		if len(lastSent) > 4096 {
			lastSent = make(map[bmpPeerEvidenceKey]bmpEvidenceAttempt)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.evidenceReset:
			lastSent = make(map[bmpPeerEvidenceKey]bmpEvidenceAttempt)
		case peer := <-l.evidenceQueue:
			if peer.routingPeerUp != nil {
				l.stageRoutingEvidence(ctx, peer)
				continue
			}
			now := l.now()
			key := bmpPeerEvidenceKey{sessionHandle: peer.sessionHandle, routerAgentID: peer.routerAgentID,
				peerAddress: peer.peerAddress, peerASN: peer.peerASN,
				routerSerial: peer.routerSerial}
			if peer.observedAt.IsZero() || !peer.observedAt.After(now.Add(-bmpEvidenceMaxLag)) ||
				!lastSent[key].due(now) {
				continue
			}
			state := lastSent[key]
			state.attemptAt = now
			remember(key, state)
			claims, err := l.peerEvidenceClaims(peer)
			if err != nil {
				l.log.Warn("bmp canonical peer evidence invalid; raw event retained",
					"tenant_id", l.laneTenant, "error", err.Error())
				continue
			}
			accepted, unresolved, err := l.evidence.Submit(ctx, claims)
			if err != nil {
				l.log.Warn("bmp canonical peer evidence unavailable; raw event retained",
					"tenant_id", l.laneTenant, "agent_id", l.evidenceAgent,
					"error", err.Error())
				continue
			}
			if unresolved == 0 && accepted == len(claims) {
				state.acceptedAt = now
				state.partialAt = time.Time{}
			} else if accepted > 0 {
				// Only a partly accepted response can duplicate durable rows.
				// If none was accepted, attemptAt allows a one-minute retry.
				state.partialAt = now
			}
			remember(key, state)
		}
	}
}

func (l *BMPListener) peerEvidenceClaims(peer bmpPeerEvidence) ([]entity.Observation, error) {
	addr, err := netip.ParseAddr(peer.peerAddress)
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return nil, entity.ErrInvalidAlias
	}
	if peer.tenantID != l.laneTenant || peer.routerAgentID == "" || peer.routerSerial == "" {
		return nil, entity.ErrScopeMismatch
	}
	address := addr.Unmap().String()
	source := entity.SourceKey{AgentID: l.evidenceAgent, Kind: entity.BMPPeer,
		SourceRef: peer.routerAgentID}
	provenance := fmt.Sprintf("bmp:router:%s:peer-asn:%d", peer.routerAgentID, peer.peerASN)
	claims := make([]entity.Observation, 0, 2)
	for _, alias := range []entity.AliasKey{
		{Kind: entity.AddressAlias, Value: address},
		{Kind: entity.BMPPeerAlias, Value: fmt.Sprintf("%s/as%d", address, peer.peerASN)},
	} {
		id, err := crypto.UUIDv4()
		if err != nil {
			return nil, err
		}
		claims = append(claims, entity.Observation{ID: id, Source: source,
			Alias: alias, SourceRef: provenance, OriginSerial: peer.routerSerial,
			ObservedAt: peer.observedAt})
	}
	return claims, nil
}
