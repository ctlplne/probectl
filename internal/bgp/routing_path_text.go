// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"strconv"
)

// ParseRoutingPathText decodes the canonical grouping text emitted by
// ProjectRoutingPathFields. It preserves every ASN, prepend, set and confed;
// adjacent sequence segment boundaries are not encoded in this text format.
// This is a pure codec, never evidence of a sender or source authority.
func ParseRoutingPathText(ctx context.Context, text string, budget ASPathParseBudget) ([]ASPathSegment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if budget.MemoryBytes < 128 || budget.WorkUnits < 128 || int64(len(text)) > (budget.MemoryBytes-128)/16 || int64(len(text)) > (budget.WorkUnits-128)/16 {
		return nil, ErrASPathBudget
	}
	segments := []ASPathSegment{}
	for position := 0; position < len(text); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		segment, next, err := routingPathTextSegment(ctx, text, position)
		if err != nil {
			return nil, err
		}
		segments = append(segments, segment)
		position = next
		if position == len(text) {
			break
		}
		if text[position] != ' ' || position+1 == len(text) {
			return nil, ErrASPathSyntax
		}
		position++
	}
	return segments, nil
}

func routingPathTextSegment(ctx context.Context, text string, position int) (ASPathSegment, int, error) {
	segment := ASPathSegment{Kind: ASPathSequence}
	closing, separator := byte(0), byte(' ')
	switch text[position] {
	case '{':
		segment.Kind, closing, separator = ASPathSet, '}', ','
		position++
	case '(':
		segment.Kind, closing = ASPathConfedSequence, ')'
		position++
	case '[':
		segment.Kind, closing, separator = ASPathConfedSet, ']', ','
		position++
	}
	for {
		if err := ctx.Err(); err != nil {
			return ASPathSegment{}, 0, err
		}
		start := position
		for position < len(text) && text[position] >= '0' && text[position] <= '9' {
			position++
			if position-start > 10 {
				return ASPathSegment{}, 0, ErrASPathSyntax
			}
		}
		if start == position {
			return ASPathSegment{}, 0, ErrASPathSyntax
		}
		digits := text[start:position]
		value, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != digits {
			return ASPathSegment{}, 0, ErrASPathSyntax
		}
		segment.Values = append(segment.Values, uint32(value))
		if closing != 0 {
			if position == len(text) {
				return ASPathSegment{}, 0, ErrASPathSyntax
			}
			if text[position] == closing {
				return segment, position + 1, nil
			}
			if text[position] != separator {
				return ASPathSegment{}, 0, ErrASPathSyntax
			}
			position++
			continue
		}
		if position == len(text) || text[position] != ' ' {
			return segment, position, nil
		}
		// A following set/confed is another segment. Consecutive bare ASNs
		// belong to the same textual sequence, including repeated prepends.
		if position+1 == len(text) || text[position+1] < '0' || text[position+1] > '9' {
			return segment, position, nil
		}
		position++
	}
}
