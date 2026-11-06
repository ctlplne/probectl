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

// RouteAttribute retains one complete wire attribute. Unknown attributes,
// original flags, order and duplicates remain explicit for semantic handling.
// A present empty value is non-nil, distinct from a missing mandatory path.
type RouteAttribute struct {
	Flags, Type byte
	Value       []byte
}

// RouteAttributeBudget admits the entire two-pass operation. MemoryBytes
// conservatively charges 64 bytes per input byte for descriptors and owned
// values; WorkUnits charges two byte passes. It does not cap attribute count.
type RouteAttributeBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrRouteAttributes      = errors.New("bgp: malformed route attribute framing")
	ErrRouteAttributeBudget = errors.New("bgp: route attribute operation admission exceeded")
)

// ParseBGPRouteAttributes validates the complete attribute block before
// allocating output. This is framing, not UPDATE acceptance: callers still
// enforce known flags, mandatory attributes, duplicate/error treatment and
// source-negotiated semantics before applying a routing change.
func ParseBGPRouteAttributes(ctx context.Context, raw []byte, budget RouteAttributeBudget) ([]RouteAttribute, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/64 || int64(len(raw)) > budget.WorkUnits/2 {
		return nil, ErrRouteAttributeBudget
	}
	count := 0
	for offset := 0; offset < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, length, err := routeAttributeLength(raw[offset:])
		if err != nil {
			return nil, err
		}
		offset += header + length
		count++
	}
	out := make([]RouteAttribute, 0, count)
	for offset := 0; offset < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, length, err := routeAttributeLength(raw[offset:])
		if err != nil {
			return nil, err
		}
		value := make([]byte, length)
		copy(value, raw[offset+header:offset+header+length])
		out = append(out, RouteAttribute{Flags: raw[offset], Type: raw[offset+1], Value: value})
		offset += header + length
	}
	return out, nil
}

func routeAttributeLength(raw []byte) (header, length int, err error) {
	if len(raw) < 3 {
		return 0, 0, ErrRouteAttributes
	}
	header, length = 3, int(raw[2])
	if raw[0]&0x10 != 0 {
		if len(raw) < 4 {
			return 0, 0, ErrRouteAttributes
		}
		header, length = 4, int(binary.BigEndian.Uint16(raw[2:4]))
	}
	if length > len(raw)-header {
		return 0, 0, ErrRouteAttributes
	}
	return header, length, nil
}
