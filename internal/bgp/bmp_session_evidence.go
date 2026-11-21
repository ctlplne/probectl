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
	"math"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type bmpSessionEvidenceWriter interface {
	SubmitBMPSessionEvidence(context.Context, *agentv1.BmpSessionEvidence) error
}

type bmpSessionEvidenceStream struct {
	connection, router, serial string
	sequence                   int64
	updates                    map[bmpSessionUpdateKey]*agentv1.BmpSessionUpdateWindow
	windowStart                time.Time
}

func (l *BMPListener) newBMPSessionEvidence(id bmpIdentity) *bmpSessionEvidenceStream {
	if l.sessionEvidence == nil || id.TenantID != l.laneTenant {
		return nil
	}
	connection, err := crypto.UUIDv4()
	if err != nil {
		l.log.Warn("BMP session evidence could not start", "tenant_id", l.laneTenant)
		return nil
	}
	return &bmpSessionEvidenceStream{connection: connection, router: id.AgentID, serial: id.Serial}
}

func (stream *bmpSessionEvidenceStream) next(at time.Time) *agentv1.BmpSessionEvidence {
	if stream.sequence >= math.MaxInt64-1 {
		return nil
	}
	stream.sequence++
	return &agentv1.BmpSessionEvidence{ConnectionId: stream.connection, ConfiguredRef: stream.router,
		OriginSerial: stream.serial, Sequence: stream.sequence, ObservedUnixNanos: at.UnixNano()}
}

func (l *BMPListener) queueBMPSessionEvidence(stream *bmpSessionEvidenceStream, kind byte, payload []byte) {
	item := stream.next(l.now().UTC())
	if item == nil {
		return
	}
	item.Frame = make([]byte, bmpCommonHeaderLen+len(payload))
	item.Frame[0], item.Frame[5] = bmpVersion, kind
	binary.BigEndian.PutUint32(item.Frame[1:5], uint32(len(item.Frame)))
	copy(item.Frame[bmpCommonHeaderLen:], payload)
	l.tryBMPSessionEvidence(item)
}

func (l *BMPListener) tryBMPSessionEvidence(item *agentv1.BmpSessionEvidence) {
	select {
	case l.sessionEvidence <- item:
	default:
		if metrics, ok := l.evidence.(interface{ QueueDrop() }); ok {
			metrics.QueueDrop()
		}
	}
}

// BMPUpdateWindowInterval bounds one observed churn count. A window reports
// whole route-monitoring UPDATE frames and excludes End-of-RIB markers.
const BMPUpdateWindowInterval = 30 * time.Second

var ErrBMPUpdateWindow = errors.New("bgp: invalid BMP update observation window")

// BMPUpdateChurn counts framed updates observed in one peer view on one
// authenticated connection. A silent interval has no sample.
type BMPUpdateChurn struct {
	Peer            BMPObservationPeer `json:"peer"`
	FirstObservedAt time.Time          `json:"first_observed_at"`
	LastObservedAt  time.Time          `json:"last_observed_at"`
	Updates         uint64             `json:"updates,string"`
}

func ParseBMPUpdateWindow(window *agentv1.BmpSessionUpdateWindow, observedAt time.Time) (BMPUpdateChurn, error) {
	if window == nil || len(window.ProtoReflect().GetUnknown()) != 0 || window.FirstObservedUnixNanos <= 0 ||
		window.LastObservedUnixNanos < window.FirstObservedUnixNanos || window.LastObservedUnixNanos > observedAt.UnixNano() ||
		window.LastObservedUnixNanos-window.FirstObservedUnixNanos >= BMPUpdateWindowInterval.Nanoseconds() || window.Updates == 0 {
		return BMPUpdateChurn{}, ErrBMPUpdateWindow
	}
	header, err := ParseBMPRouteViewHeader(window.PeerHeader)
	if err != nil || !physicalPeerHeader(header) {
		return BMPUpdateChurn{}, ErrBMPUpdateWindow
	}
	return BMPUpdateChurn{Peer: observeBMPPeer(header), FirstObservedAt: time.Unix(0, window.FirstObservedUnixNanos).UTC(),
		LastObservedAt: time.Unix(0, window.LastObservedUnixNanos).UTC(), Updates: window.Updates}, nil
}

type bmpSessionUpdateKey struct {
	Address    netip.Addr
	ASN        uint32
	View       BMPRouteView
	Identifier netip.Addr
}

func (l *BMPListener) observeBMPSessionUpdate(stream *bmpSessionEvidenceStream, payload []byte) {
	if len(payload) < bmpPeerHeaderLen+bgpHeaderLen || payload[0] != 0 {
		return
	}
	header, err := ParseBMPRouteViewHeader(payload[:bmpPeerHeaderLen])
	if err != nil || !physicalPeerHeader(header) {
		l.markBMPSessionObservationGap(stream)
		return
	}
	update := payload[bmpPeerHeaderLen:]
	_, end, err := ParseBGPEndOfRIB(update)
	if err != nil || update[18] != bgpMessageTypeUpdate {
		l.markBMPSessionObservationGap(stream)
		return
	}
	if end {
		return
	}
	at := l.now().UTC()
	if !stream.windowStart.IsZero() && (at.Before(stream.windowStart) || at.Sub(stream.windowStart) >= BMPUpdateWindowInterval) {
		l.flushBMPSessionUpdates(stream, at)
	}
	key := bmpSessionUpdateKey{Address: header.PeerAddress.Unmap(), ASN: header.PeerASN, View: header.View, Identifier: header.BGPIdentifier}
	window := stream.updates[key]
	if window == nil {
		// Amortized admission comes from the existing process-wide routing
		// state budget divided across all admitted BMP connections.
		if int64(len(stream.updates)) >= l.routingStateBytes/int64(l.maxSessions)/512 {
			l.markBMPSessionObservationGap(stream)
			return
		}
		if stream.updates == nil {
			stream.updates = make(map[bmpSessionUpdateKey]*agentv1.BmpSessionUpdateWindow)
		}
		window = &agentv1.BmpSessionUpdateWindow{PeerHeader: append([]byte(nil), payload[:bmpPeerHeaderLen]...),
			FirstObservedUnixNanos: at.UnixNano()}
		stream.updates[key] = window
		if stream.windowStart.IsZero() {
			stream.windowStart = at
		}
	}
	window.Updates++
	window.LastObservedUnixNanos = at.UnixNano()
}

func (l *BMPListener) flushBMPSessionUpdates(stream *bmpSessionEvidenceStream, at time.Time) {
	for _, window := range stream.updates {
		item := stream.next(at)
		if item != nil {
			item.UpdateWindow = window
			l.tryBMPSessionEvidence(item)
		}
	}
	clear(stream.updates)
	stream.windowStart = time.Time{}
}

func (l *BMPListener) markBMPSessionObservationGap(stream *bmpSessionEvidenceStream) {
	// Discard the currently incomplete window and reserve an unused sequence.
	clear(stream.updates)
	stream.windowStart = time.Time{}
	if stream.sequence < math.MaxInt64-1 {
		stream.sequence++
	}
	if metrics, ok := l.evidence.(interface{ QueueDrop() }); ok {
		metrics.QueueDrop()
	}
}

func (l *BMPListener) endBMPSessionEvidence(ctx context.Context, stream *bmpSessionEvidenceStream) {
	at := l.now().UTC()
	l.flushBMPSessionUpdates(stream, at)
	item := stream.next(at)
	if item == nil {
		return
	}
	item.TransportClosed = true
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case l.sessionEvidence <- item:
	case <-closeCtx.Done():
		if metrics, ok := l.evidence.(interface{ QueueDrop() }); ok {
			metrics.QueueDrop()
		}
	}
}

// Keep statistics delivery distinct from routing liveness. Gaps in analytics
// sequence remain visible to the receiver when a queue or delivery drops data.
func (l *BMPListener) sessionEvidenceLoop(ctx context.Context, writer bmpSessionEvidenceWriter) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-l.sessionEvidence:
			if err := writer.SubmitBMPSessionEvidence(ctx, item); err != nil {
				l.log.Warn("BMP session evidence was not retained", "tenant_id", l.laneTenant, "agent_id", l.evidenceAgent)
			}
		}
	}
}
