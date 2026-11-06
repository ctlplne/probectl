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

// RouteASPath combines reported path semantics with explicitly ignored
// optional attribute types. It does not establish a selected/current route.
type RouteASPath struct {
	Path              ASPathReconstruction
	IgnoredAttributes []byte
}

var ErrRouteASAttributes = errors.New("bgp: invalid or ambiguous path attributes")

// reconstructRouteASPath interprets complete attributes using the BMP view's
// explicit ASN width. Missing mandatory AS_PATH, invalid relevant flags or duplicate
// relevant attributes refuse output. RFC6793/RFC7606 malformed optional aggregation
// data is discarded explicitly, never used to choose reconstruction semantics.
func reconstructRouteASPath(ctx context.Context, attributes []RouteAttribute, asnWidth int, budget ASPathParseBudget) (RouteASPath, error) {
	none := RouteASPath{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if asnWidth != 2 && asnWidth != 4 {
		return none, ErrRouteASAttributes
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(attributes)) > budget.MemoryBytes/64 || int64(len(attributes)) > budget.WorkUnits {
		return none, ErrASPathBudget
	}
	remaining := ASPathParseBudget{MemoryBytes: budget.MemoryBytes - int64(len(attributes))*64, WorkUnits: budget.WorkUnits - int64(len(attributes))}
	for _, attribute := range attributes {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if int64(len(attribute.Value)) > remaining.WorkUnits {
			return none, ErrASPathBudget
		}
		remaining.WorkUnits -= int64(len(attribute.Value))
	}
	input := ASPathAttributes{FourOctetSession: asnWidth == 4}
	var seen, ignored [256]bool
	for _, attribute := range attributes {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		switch attribute.Type {
		case 2, 7, 17, 18:
			if seen[attribute.Type] {
				return none, ErrRouteASAttributes
			}
			seen[attribute.Type] = true
		default:
			continue
		}
		switch attribute.Type {
		case 2:
			// Well-known transitive; partial/optional flags are not valid.
			if attribute.Flags&0xe0 != 0x40 {
				return none, ErrRouteASAttributes
			}
			input.Path = attribute.Value
			if input.Path == nil {
				input.Path = []byte{}
			}
		case 17:
			if asnWidth != 4 && attribute.Flags&0xc0 != 0xc0 {
				return none, ErrRouteASAttributes
			}
			input.AS4Path = attribute.Value
			if input.AS4Path == nil {
				input.AS4Path = []byte{}
			}
		case 7:
			if attribute.Flags&0xc0 != 0xc0 || len(attribute.Value) != asnWidth+4 {
				ignored[7] = true
				continue
			}
			input.AggregatorPresent = true
			if asnWidth == 4 {
				input.AggregatorASN = binary.BigEndian.Uint32(attribute.Value[:4])
			} else {
				input.AggregatorASN = uint32(binary.BigEndian.Uint16(attribute.Value[:2]))
			}
		case 18:
			if asnWidth == 4 || attribute.Flags&0xc0 != 0xc0 || len(attribute.Value) != 8 {
				ignored[18] = true
				continue
			}
			input.AS4AggregatorPresent = true
		}
	}
	if !seen[2] {
		return none, ErrRouteASAttributes
	}
	path, err := ReconstructASPath(ctx, input, remaining)
	if err != nil {
		return none, err
	}
	if seen[17] && path.AS4Action != "reconstructed" {
		ignored[17] = true
	}
	if input.AggregatorPresent && input.AS4AggregatorPresent {
		if input.AggregatorASN == 23456 {
			ignored[7] = true
		} else {
			ignored[18] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	out := RouteASPath{Path: path}
	for _, kind := range []byte{7, 17, 18} {
		if ignored[kind] {
			out.IgnoredAttributes = append(out.IgnoredAttributes, kind)
		}
	}
	return out, nil
}
