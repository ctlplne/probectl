// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
)

func TestParseBGPUpdateRouteLimits(t *testing.T) {
	t.Run("AS path exact", func(t *testing.T) {
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, maxBMPASPathEntries, 1),
		)
		if err != nil {
			t.Fatalf("exact AS_PATH limit rejected: %v", err)
		}
		if len(routes) != 1 || len(routes[0].ASPath) != maxBMPASPathEntries {
			t.Fatalf("exact AS_PATH routes = %+v", routes)
		}
	})

	t.Run("AS path one past", func(t *testing.T) {
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, maxBMPASPathEntries+1, 1),
		)
		if !errors.Is(err, errBMPASPathLimit) {
			t.Fatalf("one-past AS_PATH error = %v, want %v", err, errBMPASPathLimit)
		}
		if routes != nil {
			t.Fatalf("one-past AS_PATH constructed %d routes", len(routes))
		}
	})

	t.Run("announcements exact", func(t *testing.T) {
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, 1, maxBMPRouteAnnouncements),
		)
		if err != nil {
			t.Fatalf("exact announcement limit rejected: %v", err)
		}
		if len(routes) != maxBMPRouteAnnouncements {
			t.Fatalf("exact announcement routes = %d, want %d", len(routes), maxBMPRouteAnnouncements)
		}
	})

	t.Run("announcements one past", func(t *testing.T) {
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, 1, maxBMPRouteAnnouncements+1),
		)
		if !errors.Is(err, errBMPAnnouncementLimit) {
			t.Fatalf("one-past announcement error = %v, want %v", err, errBMPAnnouncementLimit)
		}
		if routes != nil {
			t.Fatalf("one-past announcements constructed %d routes", len(routes))
		}
	})

	t.Run("aggregate exact and shared", func(t *testing.T) {
		announcements := maxBMPRoutePathEntries / maxBMPASPathEntries
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, maxBMPASPathEntries, announcements),
		)
		if err != nil {
			t.Fatalf("exact aggregate limit rejected: %v", err)
		}
		if len(routes) != announcements {
			t.Fatalf("exact aggregate routes = %d, want %d", len(routes), announcements)
		}
		if len(routes) > 1 && &routes[0].ASPath[0] != &routes[1].ASPath[0] {
			t.Fatal("routes cloned AS_PATH instead of sharing the immutable parsed path")
		}
	})

	t.Run("aggregate one past", func(t *testing.T) {
		announcements := maxBMPRoutePathEntries/maxBMPASPathEntries + 1
		routes, err := parseBGPUpdateRoutes(
			buildCardinalityBGPUpdate(t, maxBMPASPathEntries, announcements),
		)
		if !errors.Is(err, errBMPRoutePathWorkLimit) {
			t.Fatalf("one-past aggregate error = %v, want %v", err, errBMPRoutePathWorkLimit)
		}
		if routes != nil {
			t.Fatalf("one-past aggregate constructed %d routes", len(routes))
		}
	})
}

func TestBMPReaderRejectsOverLimitUpdate(t *testing.T) {
	server, client := bmpTLSPipe(t)
	pub := &capturePublisher{}
	inventory := NewBMPPeerInventory()
	listener := NewBMPListener(nil, pub, "bounds", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(time.Second),
		WithBMPPeerInventory(inventory),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()

	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	seenAt := time.Unix(1_700_000_000, 0)
	overLimit := buildBMPRouteMonitoringUpdate(
		t,
		64511,
		"192.0.2.11",
		buildCardinalityBGPUpdate(
			t,
			maxBMPASPathEntries,
			maxBMPRoutePathEntries/maxBMPASPathEntries+1,
		),
		seenAt,
	)
	if _, err := client.Write(overLimit); err != nil {
		t.Fatalf("write over-limit UPDATE: %v", err)
	}

	valid := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seenAt)
	if _, err := client.Write(valid); err != nil {
		t.Fatalf("write valid UPDATE after rejection: %v", err)
	}

	messages := waitCaptured(t, pub, 1)
	if len(messages) != 1 {
		t.Fatalf("published %d events, want only the valid post-rejection event", len(messages))
	}
	var event bgpv1.BGPEvent
	if err := proto.Unmarshal(messages[0].value, &event); err != nil {
		t.Fatalf("unmarshal published event: %v", err)
	}
	if event.GetPrefix() != "203.0.113.0/24" || event.GetTenantId() != "tenant-a" {
		t.Fatalf("published event = %+v, want tenant-a valid post-rejection route", &event)
	}
	if path := event.GetNewAsPath(); len(path) != 2 || path[0] != 64511 || path[1] != 64500 {
		t.Fatalf("published AS path = %v, want [64511 64500]", path)
	}

	peers := inventory.Snapshot()
	if len(peers) != 1 || peers[0].TenantID != "tenant-a" || peers[0].RouteAnnouncements != 1 {
		t.Fatalf("inventory after rejected UPDATE = %+v, want one valid tenant-a announcement", peers)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener after bounded rejection: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not exit after client close")
	}
}

// buildCardinalityBGPUpdate creates small deterministic cardinality fixtures.
// It deliberately supports multiple AS_SEQUENCE segments and the extended
// attribute-length encoding needed to exercise the parser's real boundaries.
func buildCardinalityBGPUpdate(t *testing.T, asPathEntries, announcements int) []byte {
	t.Helper()
	if asPathEntries < 0 || announcements < 0 {
		t.Fatalf("negative fixture cardinality: path=%d announcements=%d", asPathEntries, announcements)
	}

	segmentCount := (asPathEntries + 254) / 255
	pathValue := make([]byte, 0, asPathEntries*4+segmentCount*2)
	for remaining, offset := asPathEntries, 0; remaining > 0; {
		count := min(remaining, 255)
		pathValue = append(pathValue, 2, byte(count))
		for i := 0; i < count; i++ {
			var asn [4]byte
			binary.BigEndian.PutUint32(asn[:], uint32(64500+(offset+i)%100))
			pathValue = append(pathValue, asn[:]...)
		}
		remaining -= count
		offset += count
	}

	var asPathAttr []byte
	if len(pathValue) > 255 {
		asPathAttr = make([]byte, 4, 4+len(pathValue))
		asPathAttr[0] = 0x40 | bgpPathAttrExtended
		asPathAttr[1] = bgpPathAttrASPath
		binary.BigEndian.PutUint16(asPathAttr[2:4], uint16(len(pathValue)))
	} else {
		asPathAttr = []byte{0x40, bgpPathAttrASPath, byte(len(pathValue))}
	}
	asPathAttr = append(asPathAttr, pathValue...)

	body := make([]byte, 4, 4+len(asPathAttr)+announcements)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(asPathAttr)))
	body = append(body, asPathAttr...)
	body = append(body, make([]byte, announcements)...) // repeated IPv4 /0 NLRIs

	msgLen := bgpHeaderLen + len(body)
	if msgLen > 65535 {
		t.Fatalf("fixture BGP message length = %d, exceeds uint16", msgLen)
	}
	msg := make([]byte, msgLen)
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(msgLen))
	msg[18] = bgpMessageTypeUpdate
	copy(msg[bgpHeaderLen:], body)
	return msg
}

func buildBMPRouteMonitoringUpdate(
	t *testing.T,
	peerASN uint32,
	peerAddress string,
	update []byte,
	seenAt time.Time,
) []byte {
	t.Helper()
	payload := make([]byte, bmpPeerHeaderLen+len(update))
	address := netip.MustParseAddr(peerAddress).As4()
	copy(payload[22:26], address[:])
	binary.BigEndian.PutUint32(payload[26:30], peerASN)
	binary.BigEndian.PutUint32(payload[34:38], uint32(seenAt.Unix()))
	binary.BigEndian.PutUint32(payload[38:42], uint32(seenAt.Nanosecond()/1000))
	copy(payload[bmpPeerHeaderLen:], update)

	msg := make([]byte, bmpCommonHeaderLen+len(payload))
	msg[0] = bmpVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)))
	msg[5] = bmpRouteMonitoring
	copy(msg[bmpCommonHeaderLen:], payload)
	return msg
}
