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
	"errors"
	"net/netip"
	"testing"
)

func mrtRIBForTest(subtype uint16, lastInvalid bool) []byte {
	attributes := []byte{0x40, 1, 1, 0}
	path := asPathSegmentWire([]ASPathSegment{{Kind: 3, Values: []uint32{64496}}, {Kind: 2, Values: []uint32{^uint32(0), 64497, 64497}}, {Kind: 1, Values: []uint32{64500, 64501}}}, 4)
	attributes = append(attributes, 0x50, 2)
	attributes = binary.BigEndian.AppendUint16(attributes, uint16(len(path)))
	attributes = append(attributes, path...)
	if subtype == 4 || subtype == 10 {
		attributes = append(attributes, 0x80, 14, 17, 16)
		hop := netip.MustParseAddr("2001:db8::1").As16()
		attributes = append(attributes, hop[:]...)
	} else {
		attributes = append(attributes, 0x40, 3, 4, 192, 0, 2, 1)
	}
	body := binary.BigEndian.AppendUint32(nil, ^uint32(0))
	if subtype == 6 || subtype == 12 {
		body = append(body, 0, 1, 1)
		if subtype == 12 {
			body = binary.BigEndian.AppendUint32(body, ^uint32(0))
		}
	}
	if subtype == 4 || subtype == 10 {
		body = append(body, 32, 0x20, 1, 0x0d, 0xb8)
	} else {
		body = append(body, 24, 192, 0, 2)
	}
	body = binary.BigEndian.AppendUint16(body, 2)
	for i := range 2 {
		body = binary.BigEndian.AppendUint16(body, uint16(i))
		body = binary.BigEndian.AppendUint32(body, ^uint32(0))
		if subtype == 8 || subtype == 10 {
			body = binary.BigEndian.AppendUint32(body, uint32(i)*^uint32(0))
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(attributes)))
		if lastInvalid && i == 1 {
			bad := bytes.Clone(attributes)
			bad[0] = 0
			body = append(body, bad...)
		} else {
			body = append(body, attributes...)
		}
	}
	return mrtRecordForTest(subtype, body)
}

func TestMRTRIBKeepsWholeDualFamilyPathsAttributesClocksAndExplicitAddPath(t *testing.T) {
	budget := UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}
	for _, subtype := range []uint16{2, 4, 6, 8, 10, 12} {
		raw := mrtRIBForTest(subtype, false)
		got, err := DecodeMRTRIB(t.Context(), raw, 2, budget)
		if err != nil || len(got.Entries) != 2 || got.Sequence != ^uint32(0) || got.ObservedUnixNanos != int64(^uint32(0))*1_000_000_000 {
			t.Fatal("MRT RIB lost whole record or original clocks", subtype, got, err)
		}
		for i, entry := range got.Entries {
			segments := entry.Path.Path.Segments
			if entry.PeerIndex != uint16(i) || entry.OriginatedUnixNanos != got.ObservedUnixNanos || len(segments) != 3 || segments[0].Kind != 3 || segments[1].Values[0] != ^uint32(0) || segments[2].Kind != 1 || len(entry.NextHops) != 1 || len(entry.Attributes) != 3 {
				t.Fatal("MRT RIB flattened path identity or dropped source attributes", subtype, entry)
			}
			wantAdd := subtype == 8 || subtype == 10 || subtype == 12
			wantID := uint32(0)
			if subtype == 12 || wantAdd && i == 1 {
				wantID = ^uint32(0)
			}
			if entry.Route.HasPathID != wantAdd || entry.Route.PathID != wantID {
				t.Fatal("MRT RIB guessed or lost ADD-PATH zero/full identity", subtype, entry.Route)
			}
			if (subtype == 4 || subtype == 10) != entry.NextHops[0].Is6() {
				t.Fatal("MRT compact next-hop encoding was treated as a BMP session", subtype, entry.NextHops)
			}
		}
		clear(raw)
		if got.Entries[0].Attributes[0].Value[0] != 0 || got.Entries[0].Path.Path.Segments[1].Values[0] != ^uint32(0) {
			t.Fatal("MRT RIB retained borrowed raw source bytes")
		}
	}
}

func TestMRTRIBRefusesWholeLateMalformedForeignPeerAndUnadmittedRecords(t *testing.T) {
	budget := UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}
	valid := mrtRIBForTest(2, false)
	for _, raw := range [][]byte{mrtRIBForTest(2, true), mrtRIBForTest(10, true), mrtRIBForTest(12, true), valid[:len(valid)-1], mrtRecordForTest(2, append(bytes.Clone(valid[12:]), 0)), mrtRecordForTest(99, valid[12:])} {
		if got, err := DecodeMRTRIB(t.Context(), raw, 2, budget); err == nil || got.Entries != nil {
			t.Fatal("MRT RIB exposed an earlier path from a refused whole record", got, err)
		}
	}
	if got, err := DecodeMRTRIB(t.Context(), valid, 1, budget); err == nil || got.Entries != nil {
		t.Fatal("MRT RIB borrowed an undefined source peer", got, err)
	}
	if got, err := DecodeMRTRIB(t.Context(), valid, 2, UpdateFrameBudget{MemoryBytes: 1, WorkUnits: 1}); !errors.Is(err, ErrMRTBudget) || got.Entries != nil {
		t.Fatal("MRT RIB bypassed complete admission", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DecodeMRTRIB(ctx, valid, 2, budget); !errors.Is(err, context.Canceled) {
		t.Fatal("MRT RIB ignored cancellation", err)
	}
}

func FuzzMRTRIB(f *testing.F) {
	f.Add(mrtRIBForTest(2, false))
	f.Add(mrtRIBForTest(10, false))
	f.Add(mrtRIBForTest(12, false))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeMRTRIB(t.Context(), raw, 2, UpdateFrameBudget{MemoryBytes: 4 << 20, WorkUnits: 4 << 20})
	})
}
