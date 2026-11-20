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

func TestMRTUpdateArchivePreservesInboundPathsAndPeerChanges(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	peer := netip.MustParseAddr("198.51.100.2")
	at := uint32(1_700_000_500)
	withdraw := []byte{0, 0, 0, 0, 24, 192, 0, 2}
	announcement := []byte{0, 0, 0, 1, 24, 192, 0, 2}
	attributes := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf0, 0x40, 3, 4, 192, 0, 2, 1}
	update := endOfRIBFrameForTest(withdraw, attributes, announcement)
	inbound := mrtUpdateRecordForTest(17, 9, at, update)
	outbound := mrtUpdateRecordForTest(17, 11, at, update)
	transition := mrtUpdateRecordForTest(16, 5, at, []byte{0, 6, 0, 1})
	raw := bytes.Join([][]byte{inbound, outbound, transition}, nil)
	budget := MRTArchiveBudget{ArchiveBytes: int64(len(raw)), Records: 3,
		Frame: UpdateFrameBudget{MemoryBytes: 4 << 20, WorkUnits: 4 << 20}}
	var staged []MRTUpdate
	total, records, err := StageMRTUpdates(t.Context(), bytes.NewReader(raw), budget, func(_ context.Context, update MRTUpdate) error {
		staged = append(staged, update)
		return nil
	})
	if err != nil || total != int64(len(raw)) || records != 3 || len(staged) != 2 ||
		staged[0].PeerAddress != peer || staged[0].PeerASN != 65539 ||
		staged[0].ObservedUnixNanos != int64(at)*1_000_000_000+123456000 ||
		staged[1].OldState != 6 || staged[1].NewState != 1 || len(staged[1].Groups) != 0 {
		t.Fatalf("the archive lost exact peer state or retained a locally sent copy: %+v, %v", staged, err)
	}
	groups := staged[0].Groups
	if len(groups) != 1 || len(groups[0].Withdrawn) != 1 || len(groups[0].Announced) != 1 ||
		groups[0].Withdrawn[0] != (RoutePrefix{Prefix: prefix, PathID: 0, HasPathID: true}) ||
		groups[0].Announced[0] != (RoutePrefix{Prefix: prefix, PathID: 1, HasPathID: true}) {
		t.Fatalf("the archive did not preserve each exact ADD-PATH operation: %+v", staged[0])
	}
	for _, end := range []int{len(raw) - 1, len(inbound) + len(outbound) + mrtCommonHeaderBytes} {
		total, records, err = StageMRTUpdates(t.Context(), bytes.NewReader(raw[:end]), budget, func(context.Context, MRTUpdate) error {
			return nil
		})
		if !errors.Is(err, errMRTArchiveIncomplete) || total != 0 || records != 0 {
			t.Fatalf("the late truncated update interval acquired a receipt: %d %d %v", total, records, err)
		}
	}
}

func mrtUpdateRecordForTest(messageType, subtype uint16, timestamp uint32, payload []byte) []byte {
	var body []byte
	if messageType == 17 {
		body = binary.BigEndian.AppendUint32(body, 123456)
	}
	body = binary.BigEndian.AppendUint32(body, 65539)
	body = binary.BigEndian.AppendUint32(body, 64497)
	body = append(body, 0, 0, 0, 1, 198, 51, 100, 2, 203, 0, 113, 27)
	body = append(body, payload...)
	raw := mrtRecordForTest(subtype, body)
	binary.BigEndian.PutUint32(raw[:4], timestamp)
	binary.BigEndian.PutUint16(raw[4:6], messageType)
	return raw
}

func FuzzMRTUpdateArchive(f *testing.F) {
	attributes := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf0, 0x40, 3, 4, 192, 0, 2, 1}
	announcement := endOfRIBFrameForTest(nil, attributes, []byte{0, 0, 0, 1, 24, 192, 0, 2})
	f.Add(mrtUpdateRecordForTest(17, 9, 1_700_000_500, announcement))
	f.Add(mrtUpdateRecordForTest(16, 5, 1_700_000_500, []byte{0, 6, 0, 1}))
	f.Fuzz(func(t *testing.T, raw []byte) {
		budget := MRTArchiveBudget{ArchiveBytes: 1 << 16, Records: 32,
			Frame: UpdateFrameBudget{MemoryBytes: 4 << 20, WorkUnits: 4 << 20}}
		size, records, err := StageMRTUpdates(t.Context(), bytes.NewReader(raw), budget, func(_ context.Context, update MRTUpdate) error {
			if !update.PeerAddress.IsValid() || update.ObservedUnixNanos <= 0 {
				t.Fatal("stage callback received an update without original source facts")
			}
			return nil
		})
		if err != nil {
			if size != 0 || records != 0 {
				t.Fatal("invalid archive produced a receipt", size, records, err)
			}
			return
		}
		if size != int64(len(raw)) || records > budget.Records {
			t.Fatal("archive receipt omitted bytes or exceeded its record limit", size, records)
		}
	})
}
