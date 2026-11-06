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

// ASPathSegmentKind retains the RFC4271/RFC5065 distinction between ordered
// sequence, unordered set and confederation data. It is not a route decision.
type ASPathSegmentKind uint8

const (
	ASPathSet            ASPathSegmentKind = 1
	ASPathSequence       ASPathSegmentKind = 2
	ASPathConfedSequence ASPathSegmentKind = 3
	ASPathConfedSet      ASPathSegmentKind = 4
)

// ASPathSegment owns its complete values, including repeated ASNs. Unordered
// sets and confederations must never become a claimed ordered forwarding path.
type ASPathSegment struct {
	Kind   ASPathSegmentKind
	Values []uint32
}

// ASPathParseBudget is finite operation admission, not a logical path ceiling.
// Memory charges a conservative32bytes per segment and4per retained ASN;
// work charges both complete byte passes. Nothing is preallocated from a quota.
type ASPathParseBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrASPathSyntax = errors.New("bgp: malformed structured AS path")
	ErrASPathBudget = errors.New("bgp: structured AS path admission exceeded")
)

// ParseASPathSegments decodes an explicit negotiated2or4octet ASN width. It
// validates the WHOLE input and its resource charge before allocating output.
// It deliberately does not guess width, reconstruct AS4_PATH, infer an origin,
// select a route, or authorize the source that supplied these untrusted bytes.
func ParseASPathSegments(ctx context.Context, value []byte, width int, budget ASPathParseBudget) ([]ASPathSegment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if width != 2 && width != 4 {
		return nil, ErrASPathSyntax
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(value)) > budget.WorkUnits/2 {
		return nil, ErrASPathBudget
	}
	segments, entries := 0, 0
	for pos := 0; pos < len(value); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(value)-pos < 2 {
			return nil, ErrASPathSyntax
		}
		kind, count := ASPathSegmentKind(value[pos]), int(value[pos+1])
		if kind < ASPathSet || kind > ASPathConfedSet || count == 0 || count > (len(value)-pos-2)/width {
			return nil, ErrASPathSyntax
		}
		segments++
		entries += count
		pos += 2 + count*width
	}
	// Division/subtraction admits the complete representation without overflow.
	if int64(segments) > budget.MemoryBytes/32 {
		return nil, ErrASPathBudget
	}
	remaining := budget.MemoryBytes - int64(segments)*32
	if int64(entries) > remaining/4 {
		return nil, ErrASPathBudget
	}
	output := make([]ASPathSegment, 0, segments)
	values := make([]uint32, entries)
	offset := 0
	for pos := 0; pos < len(value); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind, count := ASPathSegmentKind(value[pos]), int(value[pos+1])
		pos += 2
		for i := 0; i < count; i++ {
			if width == 4 {
				values[offset+i] = binary.BigEndian.Uint32(value[pos : pos+4])
			} else {
				values[offset+i] = uint32(binary.BigEndian.Uint16(value[pos : pos+2]))
			}
			pos += width
		}
		// Full slice expressions prevent append from overwriting the next
		// segment's independently owned values in this shared allocation.
		output = append(output, ASPathSegment{Kind: kind, Values: values[offset : offset+count : offset+count]})
		offset += count
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output, nil
}
