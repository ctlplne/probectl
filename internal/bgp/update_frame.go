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

// UpdateFrame keeps all three UPDATE regions as complete owned values.
// Prefix bytes need explicit source-negotiated decoding; empty regions alone
// cannot complete a route generation. Attributes still need semantic handling.
type UpdateFrame struct {
	WithdrawnIPv4, ReachableIPv4 []byte
	Attributes                   []RouteAttribute
	EndOfRIB                     RouteFamily
	HasEndOfRIB                  bool
}

// UpdateFrameBudget admits complete framing, attribute parsing and owned
// copies together. MemoryBytes charges 128 bytes per input byte; WorkUnits
// charges eight passes, including the nested parser and synchronization check.
type UpdateFrameBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrBGPUpdateFrame       = errors.New("bgp: malformed update frame")
	ErrBGPUpdateFrameBudget = errors.New("bgp: update frame operation admission exceeded")
)

// ParseBGPUpdateFrame validates one whole BGP UPDATE's framing. It does not
// decide whether an UPDATE is acceptable for a source session: negotiated
// extended-message/ADD-PATH encoding, required attributes and RFC7606 error
// treatment must be established before a caller changes routing state.
func ParseBGPUpdateFrame(ctx context.Context, raw []byte, budget UpdateFrameBudget) (UpdateFrame, error) {
	none := UpdateFrame{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/128 || int64(len(raw)) > budget.WorkUnits/8 {
		return none, ErrBGPUpdateFrameBudget
	}
	if len(raw) < bgpHeaderLen+4 || raw[18] != bgpMessageTypeUpdate || int(binary.BigEndian.Uint16(raw[16:18])) != len(raw) {
		return none, ErrBGPUpdateFrame
	}
	for _, value := range raw[:16] {
		if value != 255 {
			return none, ErrBGPUpdateFrame
		}
	}
	withdrawnLength := int(binary.BigEndian.Uint16(raw[19:21]))
	if withdrawnLength > len(raw)-bgpHeaderLen-4 {
		return none, ErrBGPUpdateFrame
	}
	withdrawn := raw[21 : 21+withdrawnLength]
	offset := 21 + withdrawnLength
	attributeLength := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	if attributeLength > len(raw)-offset {
		return none, ErrBGPUpdateFrame
	}
	attributes, err := ParseBGPRouteAttributes(ctx, raw[offset:offset+attributeLength], RouteAttributeBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 4})
	if err != nil {
		return none, errors.Join(ErrBGPUpdateFrame, err)
	}
	family, end, err := ParseBGPEndOfRIB(raw)
	if err != nil {
		return none, errors.Join(ErrBGPUpdateFrame, err)
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	out := UpdateFrame{WithdrawnIPv4: append([]byte{}, withdrawn...), ReachableIPv4: append([]byte{}, raw[offset+attributeLength:]...), Attributes: attributes, EndOfRIB: family, HasEndOfRIB: end}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}
