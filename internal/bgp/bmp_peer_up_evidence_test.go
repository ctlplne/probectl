// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestBMPPeerUpEvidenceRefusesForeignIncompleteAndUnboundSources(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, name := range []string{"foreign tenant", "missing serial", "no admitted session", "truncated OPEN", "incomplete tail", "ASN mismatch", "unknown flags", "multicast peer", "non-global peer", "fabricated Loc-RIB", "budget", "canceled"} {
		t.Run(name, func(t *testing.T) {
			listener := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane(tenant, "same-lane"), WithBMPEntityEvidence("same-listener", fakeBMPEvidence{}))
			frame := observedPeerUpFrame(t, "2001:db8::7", 4294967295)
			id := bmpIdentity{TenantID: tenant, AgentID: "same-router", Serial: "abc"}
			session := uint64(1)
			ctx := t.Context()
			switch name {
			case "foreign tenant":
				id.TenantID = "66666666-6666-4666-8666-666666666666"
			case "missing serial":
				id.Serial = ""
			case "no admitted session":
				session = 0
			case "truncated OPEN":
				frame = frame[:len(frame)-1]
			case "incomplete tail":
				frame = append(frame, 1)
			case "ASN mismatch":
				binary.BigEndian.PutUint32(frame[32:36], 65011)
			case "unknown flags":
				frame[7] |= 4
			case "multicast peer":
				value := netip.MustParseAddr("ff02::1").As16()
				copy(frame[16:32], value[:])
			case "non-global peer":
				frame[6] = 1
			case "fabricated Loc-RIB":
				frame[6] = 3
			case "budget":
				listener.routingStateBytes = 1
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			original := append([]byte{}, frame...)
			got, err := listener.physicalPeerUpEvidence(ctx, bmpPeerEvidence{tenantID: id.TenantID, routerAgentID: id.AgentID, routerSerial: id.Serial, sessionHandle: session, physicalPeerUp: frame, observedAt: time.Now()})
			if err == nil || !reflect.DeepEqual(got, bmpPeerEvidence{}) || len(listener.evidenceQueue) != 0 || !bytes.Equal(original, frame) {
				t.Fatal("refused source exposed or changed physical peer evidence", name, err)
			}
		})
	}
}

func TestBMPPeerUpEvidencePreservesReceiptClockAndOwnedWholeFrame(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	listener := NewBMPListener(nil, nil, "", nil, WithBMPTenantLane(tenant, "same-lane"), WithBMPEntityEvidence("same-listener", fakeBMPEvidence{}))
	first := time.Now().UTC()
	listener.now = func() time.Time { return first }
	frame := observedPeerUpFrame(t, "2001:db8::7", 4294967295)
	if err := listener.queuePhysicalPeerUpEvidence(t.Context(), bmpIdentity{TenantID: tenant, AgentID: "same-router", Serial: "abc"}, 1, frame[6:]); err != nil {
		t.Fatal(err)
	}
	pending := <-listener.evidenceQueue
	frame[len(frame)-1] ^= 255
	listener.now = func() time.Time { return first.Add(time.Hour) }
	got, err := listener.physicalPeerUpEvidence(t.Context(), pending)
	if err != nil || got.observedAt != first || got.peerAddress != "2001:db8::7" || got.peerASN != 4294967295 {
		t.Fatal("queued peer was restamped or borrowed mutable source bytes", got, err)
	}
}

func observedPeerUpFrame(t *testing.T, address string, asn uint32) []byte {
	t.Helper()
	caps := binary.BigEndian.AppendUint32([]byte{65, 4}, asn)
	open := routeOpenForTest(caps, false)
	wireAS := uint16(23456)
	if asn <= 65535 {
		wireAS = uint16(asn)
	}
	binary.BigEndian.PutUint16(open[20:22], wireAS)
	raw := peerUpFrameForTest(open, open, nil)
	binary.BigEndian.PutUint32(raw[32:36], asn)
	peer := netip.MustParseAddr(address)
	if peer.Is4() {
		value := peer.As4()
		copy(raw[28:32], value[:])
	} else {
		raw[7] |= 0x80
		value := peer.As16()
		copy(raw[16:32], value[:])
		local := netip.MustParseAddr("2001:db8::10").As16()
		copy(raw[48:64], local[:])
	}
	return raw
}

// Real mTLS listener; issued-identity verifier and restricted RPC receiver are
// modeled. No route UPDATE is sent: neighbor identity must be independent of
// the legacy route-event parser's AFI/ADD-PATH support.
func TestBMPPeerUpEvidenceKeepsBothFamiliesAndTenantBoundOrigins(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		t.Run(tenant, func(t *testing.T) {
			calls := make(chan []entity.Observation, 4)
			stack := startBMPTestStack(t, WithBMPTenantLane(tenant, "same-lane"), WithBMPEntityEvidence("same-listener", capturedBMPEvidence{calls: calls}))
			defer stack.stop()
			cert, key, _ := stack.issue(tenant, "same-router", time.Hour)
			conn, err := stack.dial(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			for _, address := range []string{"2001:db8::7", "192.0.2.7"} {
				at := time.Now().UTC()
				// A complete but inconsistent source frame precedes the good
				// one on the same socket/worker FIFO. It must publish nothing.
				bad := observedPeerUpFrame(t, address, 4294967295)
				binary.BigEndian.PutUint32(bad[32:36], 65011)
				if _, err := conn.Write(bad); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write(observedPeerUpFrame(t, address, 4294967295)); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-calls:
					if len(got) != 2 || got[0].Alias != (entity.AliasKey{Kind: entity.AddressAlias, Value: address}) || got[1].Alias != (entity.AliasKey{Kind: entity.BMPPeerAlias, Value: address + "/as" + strconv.FormatUint(4294967295, 10)}) {
						t.Fatal("physical Peer Up lost complete address/ASN evidence", got)
					}
					for _, claim := range got {
						if claim.Source != (entity.SourceKey{AgentID: "same-listener", Kind: entity.BMPPeer, SourceRef: "same-router"}) || claim.OriginSerial == "" || claim.ObservedAt.Before(at) {
							t.Fatal("Peer Up selected source ownership from its payload", claim)
						}
						if _, err := claim.Normalize(time.Now()); err != nil {
							t.Fatal(err)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("physical Peer Up did not publish independent neighbor evidence", address)
				}
			}
		})
	}
}
