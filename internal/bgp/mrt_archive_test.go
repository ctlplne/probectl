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

func TestMRTBaselineRequiresCompleteRosterAndAllStagedRecords(t *testing.T) {
	peers := mrtArchivePeerIndexForTest()
	ipv4 := mrtRIBForTest(8, false)
	ipv6 := mrtRIBForTest(10, false)
	whole := bytes.Join([][]byte{peers, ipv4, ipv6}, nil)
	budget := MRTArchiveBudget{ArchiveBytes: int64(len(whole)), Records: 3,
		Frame: UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}}
	staged := make([]MRTRIBRecord, 0, 2)
	stage := func(_ context.Context, table MRTPeerIndex, record MRTRIBRecord) error {
		if table.CollectorIdentifier != 17 || len(table.Peers) != 2 || len(record.Entries) != 2 {
			t.Fatalf("the whole source population changed during staging: %+v, %+v", table, record)
		}
		staged = append(staged, record)
		return nil
	}
	got, err := StageMRTBaseline(t.Context(), bytes.NewReader(whole), budget, stage)
	if err != nil || got.Bytes != int64(len(whole)) || got.Records != 3 || len(staged) != 2 ||
		staged[0].Family.AFI != 1 || staged[1].Family.AFI != 2 ||
		len(got.PeerIndex.Peers) != 2 || !staged[0].Entries[0].Route.HasPathID ||
		staged[1].Entries[1].Route.PathID != ^uint32(0) {
		t.Fatalf("baseline lost the collector, family or ADD-PATH identity: %+v, %v", got, err)
	}
	for _, end := range []int{len(whole) - 1, len(peers) + len(ipv4) + mrtCommonHeaderBytes} {
		staged = staged[:0]
		got, err = StageMRTBaseline(t.Context(), bytes.NewReader(whole[:end]), budget, stage)
		if !errors.Is(err, errMRTArchiveIncomplete) || got.Records != 0 || len(staged) != 1 {
			t.Fatalf("a late truncated record produced a publishable receipt: %+v, %v", got, err)
		}
	}
	if got, err := StageMRTBaseline(t.Context(), bytes.NewReader(ipv4), budget, stage); !errors.Is(err, ErrMRTRecord) || got.Records != 0 {
		t.Fatalf("a route without its original peer table produced a receipt: %+v, %v", got, err)
	}
	budget.Records = 2
	if got, err := StageMRTBaseline(t.Context(), bytes.NewReader(whole), budget, stage); !errors.Is(err, ErrMRTBudget) || got.Records != 0 {
		t.Fatalf("an archive with excess records produced a receipt: %+v, %v", got, err)
	}
}

func TestMRTArchiveAcceptsFullMPReachOnlyForMatchingPublicRIBPath(t *testing.T) {
	peers := mrtArchivePeerIndexForTest()
	budget := MRTArchiveBudget{ArchiveBytes: 4096, Records: 2,
		Frame: UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}}
	hop := netip.MustParseAddr("2001:db8::1")
	ip := hop.As16()
	value := append([]byte{0, 2, 1, 16}, ip[:]...)
	value = append(value, 0, 0)
	rib := func(nlri []byte) []byte {
		attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf0, 0x80, 14, byte(len(nlri))}
		attrs = append(attrs, nlri...)
		body := binary.BigEndian.AppendUint32(nil, 1)
		body = append(body, 0, 0, 1)
		body = binary.BigEndian.AppendUint16(body, 0)
		body = binary.BigEndian.AppendUint32(body, 1_700_000_000)
		body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
		return mrtRecordForTest(4, append(body, attrs...))
	}
	valid := rib(value)
	if decoded, err := DecodeMRTRIB(t.Context(), valid, 2, budget.Frame); !errors.Is(err, ErrMRTRecord) || len(decoded.Entries) != 0 {
		t.Fatal("the strict individually authorized MRT path accepted the archive encoding", decoded, err)
	}
	seen := 0
	stage := func(_ context.Context, _ MRTPeerIndex, record MRTRIBRecord) error {
		seen++
		if len(record.Entries) != 1 || record.Entries[0].Route.Prefix.String() != "::/0" ||
			len(record.Entries[0].NextHops) != 1 || record.Entries[0].NextHops[0] != hop {
			t.Fatal("the archive lost the enclosing route or the exact original next hop", record)
		}
		return nil
	}
	if receipt, err := StageMRTBaseline(t.Context(), bytes.NewReader(bytes.Join([][]byte{peers, valid}, nil)), budget, stage); err != nil || receipt.Records != 2 || seen != 1 {
		t.Fatal("a fully decoded matching public archive attribute was refused", receipt, err)
	}
	mismatch := append(bytes.Clone(value[:len(value)-1]), 32, 0x20, 1, 0x0d, 0xb8)
	for _, invalid := range [][]byte{mismatch, value[:len(value)-1], append(bytes.Clone(value), 0)} {
		if receipt, err := StageMRTBaseline(t.Context(), bytes.NewReader(bytes.Join([][]byte{peers, rib(invalid)}, nil)), budget, stage); err == nil || receipt.Records != 0 || seen != 1 {
			t.Fatal("a mismatched or incomplete full attribute escaped staging", receipt, err)
		}
	}
}

func mrtArchivePeerIndexForTest() []byte {
	var peerBody []byte
	peerBody = binary.BigEndian.AppendUint32(peerBody, 17)
	peerBody = binary.BigEndian.AppendUint16(peerBody, 0)
	peerBody = binary.BigEndian.AppendUint16(peerBody, 2)
	for i := range 2 {
		peerBody = append(peerBody, 2)
		peerBody = binary.BigEndian.AppendUint32(peerBody, uint32(i+1))
		peerBody = append(peerBody, 192, 0, 2, byte(i+1))
		peerBody = binary.BigEndian.AppendUint32(peerBody, uint32(64496+i))
	}
	return mrtRecordForTest(1, peerBody)
}
