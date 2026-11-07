// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publicMRTRecordForTest(view []byte, empty, fourASN bool, timestamp uint32) []byte {
	body := binary.BigEndian.AppendUint32(nil, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(view)))
	body = append(body, view...)
	if empty {
		body = binary.BigEndian.AppendUint16(body, 0)
	} else {
		body = binary.BigEndian.AppendUint16(body, 1)
		flags := byte(1)
		if fourASN {
			flags |= 2
		}
		body = append(body, flags)
		body = binary.BigEndian.AppendUint32(body, 0)
		address := netip.MustParseAddr("::ffff:192.0.2.1").As16()
		body = append(body, address[:]...)
		if fourASN {
			body = binary.BigEndian.AppendUint32(body, 64496)
		} else {
			body = binary.BigEndian.AppendUint16(body, 64496)
		}
	}
	raw := binary.BigEndian.AppendUint32(nil, timestamp)
	raw = binary.BigEndian.AppendUint16(raw, 13)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
	return append(raw, body...)
}

func publicMRTRIBRecordForTest(afi uint16, tail uint32, peer uint16, timestamp uint32, malformed bool) []byte {
	path := []byte{3, 1}
	path = binary.BigEndian.AppendUint32(path, 64496)
	path = append(path, 2, 3)
	for _, asn := range []uint32{^uint32(0), tail, tail} {
		path = binary.BigEndian.AppendUint32(path, asn)
	}
	path = append(path, 1, 2)
	for _, asn := range []uint32{64500, 64501} {
		path = binary.BigEndian.AppendUint32(path, asn)
	}
	attributes := []byte{0x40, 1, 1, 0, 0x40, 2, byte(len(path))}
	attributes = append(attributes, path...)
	subtype, count := uint16(8), 2
	if afi == 1 {
		attributes = append(attributes, 0x40, 3, 4, 192, 0, 2, 1)
	} else {
		subtype, count = 4, 1
		attributes = append(attributes, 0x80, 14, 17, 16)
		address := netip.MustParseAddr("2001:db8::1").As16()
		attributes = append(attributes, address[:]...)
	}
	body := binary.BigEndian.AppendUint32(nil, ^uint32(0))
	if afi == 1 {
		body = append(body, 24, 192, 0, 2)
	} else {
		body = append(body, 32, 0x20, 1, 0x0d, 0xb8)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(count))
	for i := range count {
		body = binary.BigEndian.AppendUint16(body, peer)
		body = binary.BigEndian.AppendUint32(body, 0)
		if afi == 1 {
			body = binary.BigEndian.AppendUint32(body, uint32(i)*^uint32(0))
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(attributes)))
		values := bytes.Clone(attributes)
		if malformed && i == count-1 {
			values[0] = 0
		}
		body = append(body, values...)
	}
	raw := binary.BigEndian.AppendUint32(nil, timestamp)
	raw = binary.BigEndian.AppendUint16(raw, 13)
	raw = binary.BigEndian.AppendUint16(raw, subtype)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
	return append(raw, body...)
}

func TestPublicMRTRoutingProjectionKeepsOriginalSourceFactsAndRefusesInvalidMetadata(t *testing.T) {
	_, profile := publicSnapshotFixture()
	if out, err := (BGPRouting{}).ApplyPublicMRTFrameInScope(t.Context(), tenancy.Scope{}, BGPPublicSnapshotMessage{}, nil, profile, 0); !errors.Is(err, entity.ErrScopeMismatch) || out.Status != "" {
		t.Fatal("raw MRT frame reached storage without tenant scope", out, err)
	}
	for _, afi := range []uint16{1, 2} {
		decoded, err := bgp.DecodeMRTRIB(t.Context(), publicMRTRIBRecordForTest(afi, 64497, 0, 1700000000, false), 1, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes, WorkUnits: profile.WorkUnits})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range decoded.Entries {
			change := publicMRTRoutingChange(entry, decoded.ObservedUnixNanos, decoded.Sequence)
			if err := validateRoutingChange(change, afi); err != nil {
				t.Fatal(err)
			}
			if len(change.Segments) != 3 || change.Segments[1].Values[0] != ^uint32(0) || len(change.Attributes.Wire) != 3 || change.Attributes.MRT == nil || change.Attributes.MRT.OriginatedUnixNanos != 0 || change.Attributes.MRT.RecordUnixNanos != 1700000000000000000 || change.Attributes.MRT.Sequence != ^uint32(0) || change.Attributes.MRT.PeerIndex != 0 {
				t.Fatal("raw MRT projection lost original source facts or complete paths", change)
			}
			change.Attributes.MRT.RecordUnixNanos = -1
			if err := validateRoutingChange(change, afi); err == nil {
				t.Fatal("raw MRT projection accepted invalid original metadata")
			}
		}
	}
	_, err := bgp.DecodeMRTRIB(t.Context(), publicMRTRIBRecordForTest(1, 64497, 0, 1700000000, true), 1, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes, WorkUnits: profile.WorkUnits})
	if err == nil || !publicMRTFrameRefusal(err) {
		t.Fatal("malformed MRT route could leave its known source current", err)
	}
}

func TestPublicMRTManifestKeepsOriginalEmptySourceAndPeerWireIdentity(t *testing.T) {
	input, profile := publicSnapshotFixture()
	input.Definitions = nil
	const sourceTimestamp = uint32(1700000000)
	clock := int64(sourceTimestamp) * 1_000_000_000
	input.SourceObservedUnixNanos = &clock
	input.SourceRecord = publicMRTRecordForTest(bytes.Repeat([]byte{0xff}, 65535), false, true, sourceTimestamp)
	peers, digest, _, err := preparePublicSnapshot(t.Context(), input, profile)
	if err != nil || len(peers) != 2 {
		t.Fatal("original MRT record failed whole peer/family admission", err)
	}
	var metadata BGPPublicRoutingPeer
	if err := json.Unmarshal(peers[0].Body, &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.ViewName) != 65535 || metadata.PeerBGPIdentifier == nil || *metadata.PeerBGPIdentifier != 0 || metadata.CollectorIdentifier == nil || *metadata.CollectorIdentifier != 0 || !metadata.PeerAddress.Is4In6() {
		t.Fatal("MRT source invented absent identifiers or narrowed binary metadata", metadata)
	}
	clear(input.SourceRecord)
	if metadata.ViewName[0] != 255 {
		t.Fatal("MRT manifest borrowed caller bytes")
	}
	input.SourceRecord = publicMRTRecordForTest([]byte{}, false, true, sourceTimestamp)
	_, four, _, err := preparePublicSnapshot(t.Context(), input, profile)
	if err != nil {
		t.Fatal(err)
	}
	input.SourceRecord = publicMRTRecordForTest([]byte{}, false, false, sourceTimestamp)
	_, two, _, err := preparePublicSnapshot(t.Context(), input, profile)
	if err != nil || two == four || two == digest {
		t.Fatal("MRT manifest lost original ASN encoding", err)
	}
	input.SourceRecord = publicMRTRecordForTest([]byte{0, 255, 1}, true, false, sourceTimestamp)
	empty, first, _, err := preparePublicSnapshot(t.Context(), input, profile)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("MRT zero-peer source lost explicit presence", err)
	}
	input.SourceRecord = publicMRTRecordForTest([]byte{0, 255, 2}, true, false, sourceTimestamp)
	_, second, _, err := preparePublicSnapshot(t.Context(), input, profile)
	if err != nil || first == second {
		t.Fatal("empty MRT source discarded original binary metadata", err)
	}
}

func TestPublicMRTManifestRefusesForgedPeerClockUnsupportedSourceAndPartialAdmission(t *testing.T) {
	input, profile := publicSnapshotFixture()
	input.Definitions = nil
	clock := int64(1700000000) * 1_000_000_000
	input.SourceObservedUnixNanos = &clock
	input.SourceRecord = publicMRTRecordForTest([]byte{}, false, true, 1700000000)
	definitions, err := publicMRTSnapshotDefinitions(t.Context(), input, profile)
	if err != nil {
		t.Fatal(err)
	}
	definitions[0].Public.PeerASN++
	input.Definitions = definitions
	if peers, _, _, err := preparePublicSnapshot(t.Context(), input, profile); err == nil || peers != nil {
		t.Fatal("MRT raw source accepted forged peer metadata", err)
	}
	input.Definitions = nil
	clock++
	if peers, _, _, err := preparePublicSnapshot(t.Context(), input, profile); err == nil || peers != nil {
		t.Fatal("MRT source receipt replaced original data clock", err)
	}
	clock--
	input.SourceRef = "other/mrt_table_dump_v2/collector"
	input.SourceRecord = publicMRTRecordForTest([]byte{}, true, false, 1700000000)
	if peers, _, _, err := preparePublicSnapshot(t.Context(), input, profile); err == nil || peers != nil {
		t.Fatal("empty MRT source bypassed source-format admission", err)
	}
	input.SourceRef = "ris/mrt_table_dump_v2/collector"
	input.SourceRecord = input.SourceRecord[:len(input.SourceRecord)-1]
	if peers, _, _, err := preparePublicSnapshot(t.Context(), input, profile); err == nil || peers != nil {
		t.Fatal("MRT source accepted a partial peer table", err)
	}
	input.SourceRecord = publicMRTRecordForTest(bytes.Repeat([]byte{255}, 65535), false, true, 1700000000)
	profile.MemoryBytes = 1 << 16
	if peers, _, _, err := preparePublicSnapshot(t.Context(), input, profile); err == nil || peers != nil {
		t.Fatal("MRT source returned a prefix after complete admission failed", err)
	}
}
