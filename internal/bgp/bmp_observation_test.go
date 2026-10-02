// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
)

// ING-17: a full-table dump (and a later re-dump) of routes whose origin never
// changes must produce ZERO origin_change events. Every such announcement is a
// plain observation. Before the fix the listener built EVERY route in EVERY
// UPDATE as an origin_change, so a 1000-route dump became 1000 origin_change
// events (and, downstream, 1000 incidents + 1000 SIEM records).
func TestBMPFullTableDumpEmitsNoOriginChange(t *testing.T) {
	const prefixCount = 1000
	prefixes := make([]string, 0, prefixCount)
	for i := 0; i < prefixCount; i++ {
		prefixes = append(prefixes, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	update := buildMultiPrefixBGPUpdate([]uint32{64511, 64500}, prefixes)
	seenAt := time.Unix(1_700_000_000, 0)
	dump := buildBMPRouteMonitoringUpdate(t, 64511, "192.0.2.11", update, seenAt)

	server, client := bmpTLSPipe(t)
	pub := &capturePublisher{}
	listener := NewBMPListener(nil, pub, "bmp-test", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(5*time.Second),
		WithBMPEventSuppression(0), // disabled: the re-dump republishes, proving "unchanged" is never an origin_change
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// First sighting of every prefix (the full table), then an identical re-dump
	// (a reconnecting router re-sends its Adj-RIB-In) — all unchanged origins.
	if _, err := client.Write(dump); err != nil {
		t.Fatalf("write first dump: %v", err)
	}
	if _, err := client.Write(dump); err != nil {
		t.Fatalf("write re-dump: %v", err)
	}

	waitForBMPMessages(t, pub, 2*prefixCount)
	time.Sleep(50 * time.Millisecond) // let any stray extra event arrive
	msgs := func() []capturedMsg {
		pub.mu.Lock()
		defer pub.mu.Unlock()
		return append([]capturedMsg(nil), pub.msgs...)
	}()
	if len(msgs) != 2*prefixCount {
		t.Fatalf("published %d events, want %d (one observation per route per dump)", len(msgs), 2*prefixCount)
	}
	originChanges := 0
	for _, m := range msgs {
		var ev bgpv1.BGPEvent
		if err := proto.Unmarshal(m.value, &ev); err != nil {
			t.Fatalf("unmarshal published event: %v", err)
		}
		if ev.GetEventType() == bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE {
			originChanges++
		}
	}
	if originChanges != 0 {
		t.Fatalf("full-table dump of unchanged routes produced %d origin_change events, want 0 (ING-17)", originChanges)
	}

	_ = client.Close()
	<-done
}

// ING-17: a GENUINE origin flip for an already-observed prefix is still a scored
// origin_change detection (never dropped). The baseline sighting is an
// observation; only the differing re-announcement is the detection, scored like
// the Python analyzer's origin_change (severity warning, confidence 0.7).
func TestBMPGenuineOriginFlipEmitsOneScoredOriginChange(t *testing.T) {
	seenAt := time.Unix(1_700_000_000, 0)
	baseline := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seenAt)
	flipped := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64999}, "203.0.113.0/24", seenAt.Add(time.Second))

	server, client := bmpTLSPipe(t)
	pub := &capturePublisher{}
	listener := NewBMPListener(nil, pub, "bmp-test", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(5*time.Second),
		WithBMPEventSuppression(time.Hour),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.Write(baseline); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	waitForBMPMessages(t, pub, 1) // the baseline sighting (an observation) publishes first
	if _, err := client.Write(flipped); err != nil {
		t.Fatalf("write origin flip: %v", err)
	}
	waitForBMPMessages(t, pub, 2)
	time.Sleep(50 * time.Millisecond)

	msgs := func() []capturedMsg {
		pub.mu.Lock()
		defer pub.mu.Unlock()
		return append([]capturedMsg(nil), pub.msgs...)
	}()
	if len(msgs) != 2 {
		t.Fatalf("published %d events, want 2 (one observation + one origin_change)", len(msgs))
	}
	originChanges := 0
	var change *bgpv1.BGPEvent
	for _, m := range msgs {
		ev := &bgpv1.BGPEvent{}
		if err := proto.Unmarshal(m.value, ev); err != nil {
			t.Fatalf("unmarshal published event: %v", err)
		}
		if ev.GetEventType() == bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE {
			originChanges++
			change = ev
		}
	}
	if originChanges != 1 {
		t.Fatalf("genuine origin flip produced %d origin_change events, want exactly 1 (ING-17)", originChanges)
	}
	if change.GetSeverity() != bgpv1.Severity_SEVERITY_WARNING {
		t.Fatalf("origin_change severity = %v, want warning (a scored detection)", change.GetSeverity())
	}
	if change.GetConfidence() != 0.7 {
		t.Fatalf("origin_change confidence = %v, want 0.7", change.GetConfidence())
	}
	if change.GetOldOriginAsn() != 64500 || change.GetNewOriginAsn() != 64999 {
		t.Fatalf("origin_change origins = %d -> %d, want 64500 -> 64999", change.GetOldOriginAsn(), change.GetNewOriginAsn())
	}

	_ = client.Close()
	<-done
}

// buildMultiPrefixBGPUpdate builds one BGP UPDATE announcing many prefixes under
// a single shared AS_PATH — the shape of a full-table dump.
func buildMultiPrefixBGPUpdate(asPath []uint32, prefixes []string) []byte {
	pathValue := []byte{2, byte(len(asPath))}
	for _, asn := range asPath {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], asn)
		pathValue = append(pathValue, b[:]...)
	}
	asPathAttr := []byte{0x40, bgpPathAttrASPath, byte(len(pathValue))}
	asPathAttr = append(asPathAttr, pathValue...)

	var nlri []byte
	for _, p := range prefixes {
		nlri = append(nlri, buildIPv4NLRI(p)...)
	}

	body := make([]byte, 0, 4+len(asPathAttr)+len(nlri))
	body = append(body, 0, 0) // withdrawn-routes length
	var attrLen [2]byte
	binary.BigEndian.PutUint16(attrLen[:], uint16(len(asPathAttr)))
	body = append(body, attrLen[:]...)
	body = append(body, asPathAttr...)
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
