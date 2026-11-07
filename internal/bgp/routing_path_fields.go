// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"strconv"
	"strings"
)

// RoutingPathFields keeps the complete reconstructed path and a stable text
// representation for Explorer grouping/filtering. Unknown derived values are
// null. This pure projection proves neither source authority nor forwarding.
// Next-hop AS is intentionally not guessed from a peer ASN or the first path
// value: its adapter needs independent same-router next-hop/neighbor evidence.
type RoutingPathFields struct {
	ASPath         []ASPathSegment `json:"as_path"`
	ASPathText     string          `json:"as_path_text"`
	OriginAS       *uint32         `json:"origin_as"`
	FirstTransitAS *uint32         `json:"first_transit_as"`
}

// ProjectRoutingPathFields never flattens unordered/confederation segments,
// removes prepends, truncates values or guesses an origin from an AS_SET.
// Resource admission covers both complete passes, copies and text output.
func ProjectRoutingPathFields(ctx context.Context, path []ASPathSegment, budget ASPathParseBudget) (RoutingPathFields, error) {
	if err := ctx.Err(); err != nil {
		return RoutingPathFields{}, err
	}
	memory, work := budget.MemoryBytes, budget.WorkUnits
	if memory < 128 || work < 1 || int64(len(path)) > (memory-128)/64 || int64(len(path)) > work/4 {
		return RoutingPathFields{}, ErrASPathBudget
	}
	memory -= 128 + int64(len(path))*64
	work -= int64(len(path)) * 4
	for _, segment := range path {
		if err := ctx.Err(); err != nil {
			return RoutingPathFields{}, err
		}
		if segment.Kind < ASPathSet || segment.Kind > ASPathConfedSet || len(segment.Values) == 0 {
			return RoutingPathFields{}, ErrASPathSyntax
		}
		if int64(len(segment.Values)) > memory/64 || int64(len(segment.Values)) > work/12 {
			return RoutingPathFields{}, ErrASPathBudget
		}
		memory -= int64(len(segment.Values)) * 64
		work -= int64(len(segment.Values)) * 12
	}
	result := RoutingPathFields{ASPath: make([]ASPathSegment, len(path))}
	var text strings.Builder
	for i, segment := range path {
		if err := ctx.Err(); err != nil {
			return RoutingPathFields{}, err
		}
		result.ASPath[i] = ASPathSegment{Kind: segment.Kind, Values: append([]uint32(nil), segment.Values...)}
		if i != 0 {
			text.WriteByte(' ')
		}
		opening, closing, separator := routingPathDelimiters(segment.Kind)
		text.WriteString(opening)
		for j, asn := range segment.Values {
			if err := ctx.Err(); err != nil {
				return RoutingPathFields{}, err
			}
			if j != 0 {
				text.WriteByte(separator)
			}
			text.WriteString(strconv.FormatUint(uint64(asn), 10))
		}
		text.WriteString(closing)
	}
	result.ASPathText = text.String()
	var err error
	result.OriginAS, result.FirstTransitAS, err = routingPathEndpoints(ctx, path)
	if err != nil {
		return RoutingPathFields{}, err
	}
	return result, nil
}

func routingPathDelimiters(kind ASPathSegmentKind) (string, string, byte) {
	switch kind {
	case ASPathSet:
		return "{", "}", ','
	case ASPathConfedSequence:
		return "(", ")", ' '
	case ASPathConfedSet:
		return "[", "]", ','
	default:
		return "", "", ' '
	}
}

func routingPathEndpoints(ctx context.Context, path []ASPathSegment) (origin, transit *uint32, err error) {
	for i := len(path) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		segment := path[i]
		if segment.Kind == ASPathConfedSequence || segment.Kind == ASPathConfedSet {
			continue
		}
		if segment.Kind == ASPathSequence {
			value := segment.Values[len(segment.Values)-1]
			if value != 0 && value != 23456 { // AS_TRANS is not a reconstructed origin.
				origin = &value
			}
		}
		break
	}
	if origin == nil {
		return nil, nil, nil
	}
	for _, segment := range path {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if segment.Kind == ASPathConfedSequence || segment.Kind == ASPathConfedSet {
			continue
		}
		if segment.Kind == ASPathSequence {
			value := segment.Values[0]
			if value != 0 && value != 23456 && value != *origin {
				transit = &value
			}
		}
		break
	}
	return origin, transit, nil
}
