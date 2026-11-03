// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"container/heap"
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"math/bits"
	"net/netip"
	"sort"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

type tagPrefixNumber struct{ high, low uint64 }

func (n tagPrefixNumber) compare(other tagPrefixNumber) int {
	if n.high < other.high {
		return -1
	}
	if n.high > other.high {
		return 1
	}
	if n.low < other.low {
		return -1
	}
	if n.low > other.low {
		return 1
	}
	return 0
}

func (n tagPrefixNumber) next() (tagPrefixNumber, bool) {
	low, carry := bits.Add64(n.low, 1, 0)
	high, overflow := bits.Add64(n.high, 0, carry)
	return tagPrefixNumber{high, low}, overflow == 0
}

func (n tagPrefixNumber) previous() tagPrefixNumber {
	low, carry := bits.Sub64(n.low, 1, 0)
	high, _ := bits.Sub64(n.high, 0, carry)
	return tagPrefixNumber{high, low}
}

// Exact decimal lexemes go directly into the typed UInt128 JSON input, with
// no floating-point/JavaScript conversion and no caller-supplied JSON token.
func (n tagPrefixNumber) decimal() json.RawMessage {
	var high, low big.Int
	high.SetUint64(n.high)
	high.Lsh(&high, 64)
	low.SetUint64(n.low)
	high.Or(&high, &low)
	return json.RawMessage(high.String())
}

func tagPrefixAddress(address netip.Addr) (tagPrefixNumber, uint8, bool) {
	if !address.IsValid() || address.Zone() != "" {
		return tagPrefixNumber{}, 0, false
	}
	if address.Is4() {
		value := address.As4()
		return tagPrefixNumber{low: uint64(binary.BigEndian.Uint32(value[:]))}, 4, true
	}
	value := address.As16()
	return tagPrefixNumber{binary.BigEndian.Uint64(value[:8]), binary.BigEndian.Uint64(value[8:])}, 6, true
}

func tagPrefixBounds(network netip.Prefix) (tagPrefixNumber, tagPrefixNumber, uint8) {
	start, family, _ := tagPrefixAddress(network.Addr())
	length := network.Bits()
	if family == 4 {
		length += 96
	}
	end := start
	if length <= 64 {
		end.high |= ^uint64(0) >> length
		end.low = ^uint64(0)
	} else {
		end.low |= ^uint64(0) >> (length - 64)
	}
	return start, end, family
}

type tagPrefixGroup struct {
	contextID string
	family    uint8
}
type tagPrefixRange struct {
	start, end tagPrefixNumber
	values     map[string]string
	winner     *tagPrefixCandidate
}
type tagPrefixCandidate struct {
	network netip.Prefix
	values  map[string]string
	active  bool
}
type tagPrefixEvent struct {
	at        tagPrefixNumber
	candidate *tagPrefixCandidate
	active    bool
}
type tagPrefixHeap []*tagPrefixCandidate

func (h tagPrefixHeap) Len() int           { return len(h) }
func (h tagPrefixHeap) Less(i, j int) bool { return h[i].network.Bits() > h[j].network.Bits() }
func (h tagPrefixHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *tagPrefixHeap) Push(value any)    { *h = append(*h, value.(*tagPrefixCandidate)) }
func (h *tagPrefixHeap) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	return value
}

func tagPrefixWinner(active *tagPrefixHeap) *tagPrefixCandidate {
	for active.Len() > 0 {
		if (*active)[0].active {
			return (*active)[0]
		}
		heap.Pop(active)
	}
	return nil
}

func validTagProjectionID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Every range is derived from one tenant's current owned canonical subjects.
// Duplicate networks keep an explicit empty winner, even when values agree.
func buildTagPrefixRanges(ctx context.Context, tenant string, vocabulary flow.QueryVocabulary, contexts map[string]bool, inputs []tags.PrefixProjection, charge func(int64) error) (map[tagPrefixGroup][]tagPrefixRange, error) {
	type networkKey struct {
		contextID string
		network   netip.Prefix
	}
	type subjectKey struct{ contextID, id string }
	networks := map[networkKey]*tagPrefixCandidate{}
	subjects := map[subjectKey]bool{}
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if input.TenantID != tenant || !validTagProjectionID(input.ContextID) || !contexts[input.ContextID] || !validTagProjectionID(input.ID) || !input.Network.IsValid() || input.Network != input.Network.Masked() || input.Network.Addr().Zone() != "" {
			return nil, ErrTagQueryScope
		}
		subject := subjectKey{input.ContextID, input.ID}
		if subjects[subject] {
			return nil, ErrTagQueryScope
		}
		subjects[subject] = true
		if err := charge(768 + int64(len(input.ContextID)+len(input.ID))); err != nil {
			return nil, err
		}
		values := map[string]string{}
		for key, value := range input.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			field, ok := vocabulary.Lookup("tag.src_prefix." + key)
			if !ok || field.TagKey != "src_prefix."+key || tags.ValidateValue(value) != nil {
				return nil, ErrTagQueryScope
			}
			if err := charge(128 + int64(len(key)+len(value))); err != nil {
				return nil, err
			}
			values[key] = value
		}
		key := networkKey{input.ContextID, input.Network}
		if old := networks[key]; old != nil {
			old.values = nil
		} else {
			networks[key] = &tagPrefixCandidate{network: input.Network, values: values}
		}
	}
	groups := map[tagPrefixGroup][]*tagPrefixCandidate{}
	for key, candidate := range networks {
		_, _, family := tagPrefixBounds(key.network)
		group := tagPrefixGroup{key.contextID, family}
		groups[group] = append(groups[group], candidate)
	}
	result := map[tagPrefixGroup][]tagPrefixRange{}
	for group, candidates := range groups {
		ranges, err := sweepTagPrefixRanges(ctx, candidates, charge)
		if err != nil {
			return nil, err
		}
		result[group] = ranges
	}
	return result, nil
}

func sweepTagPrefixRanges(ctx context.Context, candidates []*tagPrefixCandidate, charge func(int64) error) ([]tagPrefixRange, error) {
	if err := charge(int64(len(candidates)) * 2 * 384); err != nil {
		return nil, err
	}
	events := make([]tagPrefixEvent, 0, len(candidates)*2)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start, end, _ := tagPrefixBounds(candidate.network)
		events = append(events, tagPrefixEvent{start, candidate, true})
		if after, ok := end.next(); ok {
			events = append(events, tagPrefixEvent{after, candidate, false})
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].at.compare(events[j].at) < 0 })
	if len(events) == 0 {
		return nil, nil
	}
	active := &tagPrefixHeap{}
	var result []tagPrefixRange
	emit := func(start, end tagPrefixNumber, winner *tagPrefixCandidate) error {
		if winner == nil {
			return nil
		}
		if len(result) > 0 {
			last := &result[len(result)-1]
			if after, ok := last.end.next(); ok && after == start && last.winner == winner {
				last.end = end
				return nil
			}
		}
		if err := charge(256); err != nil {
			return err
		}
		result = append(result, tagPrefixRange{start: start, end: end, values: winner.values, winner: winner})
		return nil
	}
	previous := events[0].at
	for i := 0; i < len(events); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		point := events[i].at
		if point.compare(previous) > 0 {
			if err := emit(previous, point.previous(), tagPrefixWinner(active)); err != nil {
				return nil, err
			}
		}
		for i < len(events) && events[i].at == point {
			event := events[i]
			event.candidate.active = event.active
			if event.active {
				heap.Push(active, event.candidate)
			}
			i++
		}
		previous = point
	}
	if err := emit(previous, tagPrefixNumber{^uint64(0), ^uint64(0)}, tagPrefixWinner(active)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *TagQueryData) prefixValue(row Row, side, key string) string {
	exporter, err := netip.ParseAddr(row.Exporter)
	if err != nil || exporter.Zone() != "" {
		return ""
	}
	contextID := d.exporterContexts[exporter.Unmap().String()]
	if contextID == "" {
		return ""
	}
	address := row.SrcAddr
	if side == "dst_prefix" {
		address = row.DstAddr
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return ""
	}
	point, family, ok := tagPrefixAddress(ip.Unmap())
	if !ok {
		return ""
	}
	ranges := d.prefixes[tagPrefixGroup{contextID, family}]
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start.compare(point) > 0 }) - 1
	if i < 0 || ranges[i].end.compare(point) < 0 {
		return ""
	}
	return ranges[i].values[key]
}
