// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
)

// This mask dispatches complete source messages among already staged emulated
// cohorts. It supplies no canonical ownership, OPEN capability or route grant.
// Zero means no family-bearing content, never fabricated End-of-RIB.
func parseRoutingMessageFamilyMask(ctx context.Context, raw []byte, budget UpdateFrameBudget) (uint8, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/128 || int64(len(raw)) > budget.WorkUnits/8 {
		return 0, ErrBGPUpdateFrameBudget
	}
	const offset = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(raw) < offset || raw[0] != bmpVersion || raw[5] != bmpRouteMonitoring || uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)) {
		return 0, ErrBGPUpdateFrame
	}
	if _, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen:offset]); err != nil {
		return 0, err
	}
	frame, err := parseBGPUpdateFrame(ctx, raw[offset:], budget)
	if err != nil {
		return 0, err
	}
	var mask uint8
	if len(frame.WithdrawnIPv4) > 0 || len(frame.ReachableIPv4) > 0 {
		mask = 1
	}
	if frame.HasEndOfRIB {
		bit, err := routingAFIBit(frame.EndOfRIB.AFI, frame.EndOfRIB.SAFI)
		if err != nil {
			return 0, err
		}
		mask |= bit
	}
	for _, attribute := range frame.Attributes {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if attribute.Type != 14 && attribute.Type != 15 {
			continue
		}
		if len(attribute.Value) < 3 {
			return 0, ErrBGPUpdateFrame
		}
		bit, err := routingAFIBit(binary.BigEndian.Uint16(attribute.Value[:2]), attribute.Value[2])
		if err != nil {
			return 0, err
		}
		mask |= bit
	}
	return mask, nil
}

func routingAFIBit(family uint16, safi uint8) (uint8, error) {
	if family < 1 || family > 2 || safi != 1 {
		return 0, ErrRouteCapabilities
	}
	return 1 << (family - 1), nil
}
