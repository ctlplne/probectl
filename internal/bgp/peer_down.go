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

// PeerDownInformation is an opaque value in the separate Peer Down namespace.
type PeerDownInformation struct {
	Type  uint16
	Value []byte
}

// PeerDown preserves why monitoring ended. Reason 5 withdraws monitoring;
// it does not assert a physical peer failure. None of these fields authorizes
// a tenant/router/session or implicitly applies a retained-state mutation.
type PeerDown struct {
	Header        BMPRouteViewHeader
	Reason        byte
	FSMEvent      uint16
	FSMEventKnown bool
	Notification  []byte
	Information   []PeerDownInformation
}

var (
	ErrBMPPeerDown       = errors.New("bgp: malformed or inconsistent peer-down frame")
	ErrBMPPeerDownBudget = errors.New("bgp: peer-down operation admission exceeded")
)

// ParseBMPPeerDown validates the whole RFC7854/RFC9069 lifecycle message
// before exposing source metadata. A caller must invalidate an unprocessable
// source generation rather than silently keep its former routes current.
func ParseBMPPeerDown(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerDown, error) {
	none := PeerDown{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/128 || int64(len(raw)) > budget.WorkUnits/4 {
		return none, ErrBMPPeerDownBudget
	}
	const reasonOffset = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(raw) <= reasonOffset || raw[0] != bmpVersion || raw[5] != 2 || uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)) {
		return none, ErrBMPPeerDown
	}
	header, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen:reasonOffset])
	if err != nil {
		return none, ErrBMPPeerDown
	}
	reason, data := raw[reasonOffset], raw[reasonOffset+1:]
	if header.View == BMPLocRIB && reason != 6 {
		return none, ErrBMPPeerDown
	}
	out := PeerDown{Header: header, Reason: reason}
	switch reason {
	case 1, 3:
		if len(data) < bgpHeaderLen+2 || data[18] != 3 || int(binary.BigEndian.Uint16(data[16:18])) != len(data) {
			return none, ErrBMPPeerDown
		}
		for _, b := range data[:16] {
			if b != 255 {
				return none, ErrBMPPeerDown
			}
		}
		if err := ctx.Err(); err != nil {
			return none, err
		}
		out.Notification = append([]byte(nil), data...)
	case 2:
		if len(data) != 2 {
			return none, ErrBMPPeerDown
		}
		out.FSMEvent = binary.BigEndian.Uint16(data)
		out.FSMEventKnown = out.FSMEvent != 0
	case 4, 5:
		if len(data) != 0 {
			return none, ErrBMPPeerDown
		}
	case 6:
		info, err := parsePeerDownInformation(ctx, data)
		if err != nil {
			return none, err
		}
		out.Information = info
	default:
		return none, ErrBMPPeerDown
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}

func parsePeerDownInformation(ctx context.Context, raw []byte) ([]PeerDownInformation, error) {
	count := 0
	for offset := 0; offset < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(raw)-offset < 4 {
			return nil, ErrBMPPeerDown
		}
		length := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		offset += 4
		if length > len(raw)-offset {
			return nil, ErrBMPPeerDown
		}
		offset += length
		count++
	}
	out := make([]PeerDownInformation, 0, count)
	for offset := 0; offset < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind, length := binary.BigEndian.Uint16(raw[offset:offset+2]), int(binary.BigEndian.Uint16(raw[offset+2:offset+4]))
		offset += 4
		out = append(out, PeerDownInformation{Type: kind, Value: append([]byte(nil), raw[offset:offset+length]...)})
		offset += length
	}
	return out, nil
}
