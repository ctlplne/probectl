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
)

const bmpStatisticsReport = 1

const bmpLegacyAdjRIBIn BMPRouteView = "legacy_adj_rib_in"

var (
	ErrBMPStatisticsReport = errors.New("bgp: invalid BMP Statistics Report")
	ErrBMPStatisticsBudget = errors.New("bgp: BMP statistics operation admission exceeded")
)

// BMPStatisticKey identifies one original statistic and its wire scope. A
// zero AFI/SAFI pair represents the global form of a statistic.
type BMPStatisticKey struct {
	Type uint16 `json:"type"`
	AFI  uint16 `json:"afi,omitempty"`
	SAFI uint8  `json:"safi,omitempty"`
}

// BMPStatistic retains the exact unsigned value and the RIB it describes.
// A counter can wrap. A gauge can legitimately increase or decrease.
type BMPStatistic struct {
	BMPStatisticKey
	Value   uint64       `json:"value,string"`
	Counter bool         `json:"counter"`
	View    BMPRouteView `json:"view,omitempty"`
}

type BMPStatisticsReport struct {
	Peer    BMPObservationPeer `json:"peer"`
	Samples []BMPStatistic     `json:"samples"`
}

// ParseBMPStatisticsReport validates one complete BMP v3 frame. Unknown TLVs
// remain outside the sample set. Duplicate known keys cannot become data.
func ParseBMPStatisticsReport(ctx context.Context, frame []byte, budget PeerMessageBudget) (BMPStatisticsReport, error) {
	none := BMPStatisticsReport{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(frame)) > budget.MemoryBytes/128 || int64(len(frame)) > budget.WorkUnits/4 {
		return none, ErrBMPStatisticsBudget
	}
	const headerBytes = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(frame) < headerBytes+4 || len(frame) > bmpMaxMessageBytes ||
		frame[0] != bmpVersion || frame[5] != bmpStatisticsReport || binary.BigEndian.Uint32(frame[1:5]) != uint32(len(frame)) {
		return none, ErrBMPStatisticsReport
	}
	peer, err := ParseBMPRouteViewHeader(frame[bmpCommonHeaderLen:headerBytes])
	if err != nil {
		return none, err
	}
	samples := []BMPStatistic{}
	seen := map[BMPStatisticKey]bool{}
	err = scanBMPStatisticTLVs(ctx, frame[headerBytes:], func(kind uint16, data []byte) error {
		sample, known, err := parseBMPStatistic(peer.PeerType, kind, data)
		if err != nil || !known {
			return err
		}
		if seen[sample.BMPStatisticKey] {
			return ErrBMPStatisticsReport
		}
		seen[sample.BMPStatisticKey] = true
		samples = append(samples, sample)
		return nil
	})
	if err != nil {
		return none, err
	}
	return BMPStatisticsReport{Peer: observeBMPPeer(peer), Samples: samples}, nil
}

func scanBMPStatisticTLVs(ctx context.Context, raw []byte, take func(uint16, []byte) error) error {
	if len(raw) < 4 {
		return ErrBMPStatisticsReport
	}
	count := binary.BigEndian.Uint32(raw[:4])
	rest := raw[4:]
	if count == 0 || count > uint32(len(rest)/4) {
		return ErrBMPStatisticsReport
	}
	for range count {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(rest) < 4 {
			return ErrBMPStatisticsReport
		}
		kind, length := binary.BigEndian.Uint16(rest[:2]), int(binary.BigEndian.Uint16(rest[2:4]))
		rest = rest[4:]
		if length > len(rest) || kind == 65535 {
			return ErrBMPStatisticsReport
		}
		if err := take(kind, rest[:length]); err != nil {
			return err
		}
		rest = rest[length:]
	}
	if len(rest) != 0 {
		return ErrBMPStatisticsReport
	}
	return ctx.Err()
}

func parseBMPStatistic(peerType byte, kind uint16, raw []byte) (BMPStatistic, bool, error) {
	out := BMPStatistic{BMPStatisticKey: BMPStatisticKey{Type: kind}}
	width, view := bmpStatisticFormat(kind)
	if width == 0 {
		return out, false, nil
	}
	if len(raw) != width {
		return out, false, ErrBMPStatisticsReport
	}
	out.View = view
	if peerType == 3 {
		// RFC 9972 identifies these dual-use gauges as Loc-RIB by peer type.
		switch kind {
		case 26, 27, 28, 31, 32:
			out.View = BMPLocRIB
		}
	}
	switch width {
	case 4:
		out.Counter = true
		out.Value = uint64(binary.BigEndian.Uint32(raw))
	case 8:
		out.Value = binary.BigEndian.Uint64(raw)
	case 11:
		out.AFI, out.SAFI = binary.BigEndian.Uint16(raw[:2]), raw[2]
		if out.AFI == 0 || out.SAFI == 0 {
			return out, false, ErrBMPStatisticsReport
		}
		out.Value = binary.BigEndian.Uint64(raw[3:])
	}
	return out, true, nil
}

func bmpStatisticFormat(kind uint16) (width int, view BMPRouteView) {
	switch kind {
	case 0, 1, 2, 3, 4, 5, 6, 11, 12, 13:
		return 4, ""
	case 7:
		return 8, bmpLegacyAdjRIBIn
	case 8:
		return 8, BMPLocRIB
	case 9:
		return 11, bmpLegacyAdjRIBIn
	case 10:
		return 11, BMPLocRIB
	case 14, 39:
		return 8, BMPAdjRIBOutPrePolicy
	case 15:
		return 8, BMPAdjRIBOutPostPolicy
	case 16, 38, 40:
		return 11, BMPAdjRIBOutPrePolicy
	case 17, 41, 42, 43:
		return 11, BMPAdjRIBOutPostPolicy
	case 18, 33:
		return 8, BMPAdjRIBInPrePolicy
	case 19, 22, 34:
		return 11, BMPAdjRIBInPrePolicy
	case 20, 29, 31:
		return 8, BMPAdjRIBInPostPolicy
	case 21, 23, 26, 27, 28, 30, 32, 35, 36, 37:
		return 11, BMPAdjRIBInPostPolicy
	default:
		return 0, ""
	}
}
