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
	"testing"
)

var bmpSessionWireTestBudget = PeerMessageBudget{MemoryBytes: 8 << 20, WorkUnits: 1 << 20}

func bmpSessionWireFrame(kind byte, body []byte) []byte {
	raw := make([]byte, bmpCommonHeaderLen+len(body))
	raw[0], raw[5] = bmpVersion, kind
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[bmpCommonHeaderLen:], body)
	return raw
}

func bmpSessionWireTLV(kind uint16, value []byte) []byte {
	raw := binary.BigEndian.AppendUint16(nil, kind)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(value)))
	return append(raw, value...)
}

func bmpSessionWireStats(peerType byte, stats ...[]byte) []byte {
	peer := make([]byte, bmpPeerHeaderLen)
	peer[0] = peerType
	if peerType != 3 {
		peer[1] = 0x10 // Outbound flag does not select a statistic's scope.
		copy(peer[22:26], []byte{192, 0, 2, 1})
	}
	raw := binary.BigEndian.AppendUint32(peer, uint32(len(stats)))
	for _, stat := range stats {
		raw = append(raw, stat...)
	}
	return bmpSessionWireFrame(bmpStatisticsReport, raw)
}

func TestBMPStatisticsRetainsExactUnsignedValueAndScope(t *testing.T) {
	maximum := binary.BigEndian.AppendUint64(nil, math.MaxUint64)
	v4 := binary.BigEndian.AppendUint64([]byte{0, 1, 1}, 0)
	v6 := binary.BigEndian.AppendUint64([]byte{0, 2, 1}, 91)
	frame := bmpSessionWireStats(0, bmpSessionWireTLV(18, maximum), bmpSessionWireTLV(19, v4),
		bmpSessionWireTLV(19, v6), bmpSessionWireTLV(13, binary.BigEndian.AppendUint32(nil, math.MaxUint32)),
		bmpSessionWireTLV(999, []byte("future format")))
	got, err := ParseBMPStatisticsReport(t.Context(), frame, bmpSessionWireTestBudget)
	if err != nil || len(got.Samples) != 4 {
		t.Fatal("complete scoped report failed", got, err)
	}
	if got.Samples[0].View != BMPAdjRIBInPrePolicy || got.Samples[0].Value != math.MaxUint64 ||
		got.Samples[1].AFI != 1 || got.Samples[1].SAFI != 1 || got.Samples[1].Value != 0 ||
		got.Samples[2].AFI != 2 || got.Samples[2].Value != 91 || !got.Samples[3].Counter ||
		got.Samples[3].Value != math.MaxUint32 {
		t.Fatal("lost exact gauge, observed zero, address family or counter", got.Samples)
	}
	rib := bmpSessionWireStats(3, bmpSessionWireTLV(31, maximum), bmpSessionWireTLV(27, v6))
	got, err = ParseBMPStatisticsReport(t.Context(), rib, bmpSessionWireTestBudget)
	if err != nil || len(got.Samples) != 2 || got.Samples[0].View != BMPLocRIB || got.Samples[1].View != BMPLocRIB {
		t.Fatal("Loc-RIB instance statistics assigned to a remote peer", got, err)
	}
	duplicate := bmpSessionWireStats(0, bmpSessionWireTLV(19, v4), bmpSessionWireTLV(19, v4))
	for _, raw := range [][]byte{frame[:len(frame)-1], duplicate, bmpSessionWireStats(0, bmpSessionWireTLV(7, v4)), bmpSessionWireStats(0)} {
		if got, err := ParseBMPStatisticsReport(t.Context(), raw, bmpSessionWireTestBudget); err == nil || got.Samples != nil {
			t.Fatal("partial or duplicate report exposed statistics")
		}
	}
	if _, err := ParseBMPStatisticsReport(t.Context(), frame, PeerMessageBudget{MemoryBytes: 1, WorkUnits: 1}); !errors.Is(err, ErrBMPStatisticsBudget) {
		t.Fatal("overbudget report reached the decoder", err)
	}
}

func TestBMPConnectionEventValidatesEntireLifecycle(t *testing.T) {
	descr := bmpSessionWireTLV(1, []byte("Test router"))
	name := bmpSessionWireTLV(2, []byte("lab-router"))
	initiation := bmpSessionWireFrame(bmpInitiation, append(descr, name...))
	if event, err := ParseBMPConnectionEvent(t.Context(), initiation, bmpSessionWireTestBudget); err != nil || event.Terminated {
		t.Fatal("complete Initiation was not retained", event, err)
	}
	for _, reason := range []uint16{0, 2, 251} {
		frame := bmpSessionWireFrame(bmpTermination, bmpSessionWireTLV(1, binary.BigEndian.AppendUint16(nil, reason)))
		event, err := ParseBMPConnectionEvent(t.Context(), frame, bmpSessionWireTestBudget)
		if err != nil || !event.Terminated || event.Reason != reason || event.ReasonKnown != (reason <= 4) {
			t.Fatal("lost explicit reason, observed zero or unknown code", event, err)
		}
	}
	for _, raw := range [][]byte{initiation[:len(initiation)-1], bmpSessionWireFrame(bmpInitiation, name),
		bmpSessionWireFrame(bmpTermination, bmpSessionWireTLV(0, []byte("missing reason")))} {
		if event, err := ParseBMPConnectionEvent(t.Context(), raw, bmpSessionWireTestBudget); err == nil || event.Terminated {
			t.Fatal("incomplete lifecycle was published")
		}
	}
}

func FuzzBMPStatisticsReport(f *testing.F) {
	f.Add(bmpSessionWireStats(3, bmpSessionWireTLV(31, binary.BigEndian.AppendUint64(nil, 91))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		report, err := ParseBMPStatisticsReport(context.Background(), raw, bmpSessionWireTestBudget)
		if err != nil && report.Samples != nil {
			t.Fatal("invalid frame produced a partial statistics result")
		}
	})
}

func FuzzBMPConnectionEvent(f *testing.F) {
	f.Add(bmpSessionWireFrame(bmpTermination, bmpSessionWireTLV(1, []byte{0, 2})))
	f.Add(bmpSessionWireFrame(bmpInitiation, append(bmpSessionWireTLV(1, []byte("lab")), bmpSessionWireTLV(2, []byte("router"))...)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		event, err := ParseBMPConnectionEvent(context.Background(), raw, bmpSessionWireTestBudget)
		if err != nil && event.Terminated {
			t.Fatal("invalid frame produced a terminal event")
		}
	})
}

func TestBMPStatisticRangeKeepsZeroMissingAndGapSeparate(t *testing.T) {
	key := BMPStatisticKey{Type: 19, AFI: 1, SAFI: 1}
	spec := BMPStatisticRange{BMPStatisticKey: key, Minimum: 0, Maximum: math.MaxUint64}
	if !spec.Valid() || (BMPStatisticRange{BMPStatisticKey: BMPStatisticKey{Type: 13}}).Valid() {
		t.Fatal("only an exact RIB gauge can be compared with an expected range")
	}
	report := &BMPStatisticsReport{Samples: []BMPStatistic{{BMPStatisticKey: key, Value: 0}}}
	if spec.Evaluate(report, false) != "within_range" || spec.Evaluate(report, true) != "coverage_gap" {
		t.Fatal("observed zero and a gap were confused")
	}
	spec.AFI = 2
	if spec.Evaluate(report, false) != "missing" {
		t.Fatal("an IPv4 sample fabricated an IPv6 observation")
	}
}
