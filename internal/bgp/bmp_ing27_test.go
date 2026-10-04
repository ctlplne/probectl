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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
)

// ing27Update frames withdrawn/attrs/nlri into an embedded BGP UPDATE message.
func ing27Update(withdrawn, attrs, nlri []byte) []byte {
	body := make([]byte, 0, 4+len(withdrawn)+len(attrs)+len(nlri))
	var wl, al [2]byte
	binary.BigEndian.PutUint16(wl[:], uint16(len(withdrawn)))
	body = append(body, wl[:]...)
	body = append(body, withdrawn...)
	binary.BigEndian.PutUint16(al[:], uint16(len(attrs)))
	body = append(body, al[:]...)
	body = append(body, attrs...)
	body = append(body, nlri...)

	msg := make([]byte, bgpHeaderLen+len(body))
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(len(msg)))
	msg[18] = bgpMessageTypeUpdate
	copy(msg[bgpHeaderLen:], body)
	return msg
}

// ing27ASPathAttr builds a well-formed AS_PATH path attribute (one AS_SEQUENCE).
func ing27ASPathAttr(asns ...uint32) []byte {
	value := []byte{2, byte(len(asns))}
	for _, asn := range asns {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], asn)
		value = append(value, b[:]...)
	}
	return append([]byte{0x40, bgpPathAttrASPath, byte(len(value))}, value...)
}

// ING-27: an ADD-PATH (RFC 7911) v4 UPDATE prepends a 4-byte path id before each
// NLRI. The v4 parser must never read the path-id's leading zero byte as a
// 0-length prefix and emit a phantom 0.0.0.0/0 — it rejects the update instead.
func TestParseBGPUpdateRejectsAddPathV4(t *testing.T) {
	// path-id 0x00000001 then a would-be 203.0.113.0/24.
	nlri := []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0xCB, 0x00, 0x71}
	routes, err := parseBGPUpdateRoutes(ing27Update(nil, ing27ASPathAttr(64500), nlri))
	if !errors.Is(err, errBMPUnsupportedUpdate) {
		t.Fatalf("ADD-PATH update must be rejected as unsupported, got routes=%v err=%v", routes, err)
	}
	for _, r := range routes {
		if r.Prefix == "0.0.0.0/0" {
			t.Fatalf("ADD-PATH misparse fabricated a phantom default route: %+v", r)
		}
	}
	if len(routes) != 0 {
		t.Fatalf("a rejected update must emit no routes, got %v", routes)
	}
}

// ING-27: an IPv6 announcement rides in MP_REACH_NLRI (attribute type 14), not
// the trailing v4 NLRI field, so the v4 parser rejects it with a signal rather
// than returning zero routes silently.
func TestParseBGPUpdateRejectsIPv6MPReach(t *testing.T) {
	// A minimal MP_REACH_NLRI attribute (type 14): AFI=2 (IPv6), SAFI=1,
	// nexthop len 0, reserved 0, NLRI 2001:db8::/32. Content beyond the type is
	// not decoded — presence of the attribute is the reject trigger.
	mpValue := []byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x20, 0x20, 0x01, 0x0d, 0xb8}
	mpAttr := append([]byte{0x80, bgpPathAttrMPReachNLRI, byte(len(mpValue))}, mpValue...)
	attrs := append(ing27ASPathAttr(64500), mpAttr...)
	routes, err := parseBGPUpdateRoutes(ing27Update(nil, attrs, nil))
	if !errors.Is(err, errBMPUnsupportedUpdate) {
		t.Fatalf("MP_REACH (IPv6) update must be rejected, got routes=%v err=%v", routes, err)
	}
	if len(routes) != 0 {
		t.Fatalf("a rejected update must emit no routes, got %v", routes)
	}
}

// ING-27: a withdrawal (non-empty Withdrawn Routes field) must be rejected with
// a signal, not silently skipped.
func TestParseBGPUpdateRejectsWithdrawal(t *testing.T) {
	withdrawn := []byte{0x18, 0xCB, 0x00, 0x71} // withdraw 203.0.113.0/24
	routes, err := parseBGPUpdateRoutes(ing27Update(withdrawn, nil, nil))
	if !errors.Is(err, errBMPUnsupportedUpdate) {
		t.Fatalf("withdrawal update must be rejected, got routes=%v err=%v", routes, err)
	}
	if len(routes) != 0 {
		t.Fatalf("a rejected update must emit no routes, got %v", routes)
	}
}

// ING-27 end-to-end: interleaving ADD-PATH, IPv6 and withdrawal frames with one
// valid v4 announcement publishes exactly the valid route (never a phantom) and
// counts three unsupported updates.
func TestBMPUnsupportedUpdatesCounted(t *testing.T) {
	server, client := bmpTLSPipe(t)
	pub := &capturePublisher{}
	inventory := NewBMPPeerInventory()
	metrics := &bmpSessionMetricsCapture{}
	listener := NewBMPListener(nil, pub, "ing27", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(time.Second),
		withBMPPeerInventory(inventory),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
		WithBMPSessionMetrics(metrics),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server, nil) }()

	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	seenAt := time.Unix(1_700_000_000, 0)
	mpValue := []byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x20, 0x20, 0x01, 0x0d, 0xb8}
	mpAttr := append([]byte{0x80, bgpPathAttrMPReachNLRI, byte(len(mpValue))}, mpValue...)
	unsupported := [][]byte{
		ing27Update(nil, ing27ASPathAttr(64511), []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0xCB, 0x00, 0x71}), // ADD-PATH
		ing27Update(nil, append(ing27ASPathAttr(64511), mpAttr...), nil),                                 // IPv6 MP_REACH
		ing27Update([]byte{0x18, 0xCB, 0x00, 0x71}, nil, nil),                                            // withdrawal
	}
	for _, u := range unsupported {
		if _, err := client.Write(buildBMPRouteMonitoringUpdate(t, 64511, "192.0.2.11", u, seenAt)); err != nil {
			t.Fatalf("write unsupported UPDATE: %v", err)
		}
	}
	valid := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seenAt)
	if _, err := client.Write(valid); err != nil {
		t.Fatalf("write valid UPDATE: %v", err)
	}

	messages := waitCaptured(t, pub, 1)
	if len(messages) != 1 {
		t.Fatalf("published %d events, want only the one valid route", len(messages))
	}
	var event bgpv1.BGPEvent
	if err := proto.Unmarshal(messages[0].value, &event); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if event.GetPrefix() != "203.0.113.0/24" {
		t.Fatalf("published prefix = %q, want the valid 203.0.113.0/24 (never a phantom)", event.GetPrefix())
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit")
	}
	if got := metrics.unsupported.Load(); got != 3 {
		t.Fatalf("unsupported-update metric = %d, want 3 (ADD-PATH + IPv6 + withdrawal)", got)
	}
}
