// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"math"
	"net/netip"
	"sort"
)

const maxChangeObservations = 64 * 16

// ChangeRound retains the comparable facts from one completed discovery. An
// absent ASN denotes unavailable origin attribution for that responder.
type ChangeRound struct {
	TargetIP   string              `json:"target_ip"`
	Vantage    string              `json:"vantage"`
	Fidelity   MeasurementFidelity `json:"fidelity"`
	TraceCount int                 `json:"trace_count"`
	Hops       []ChangeHop         `json:"hops"`
	Segments   []ChangeSegment     `json:"segments"`
}

type ChangeHop struct {
	TTL        int      `json:"ttl"`
	Responders []string `json:"responders"`
	Origins    []uint32 `json:"origins,omitempty"`
}

// ChangeSegment describes an observed same-flow adjacency. Delta bounds come
// from the two responders' RTTs to the vantage. Return paths can differ.
type ChangeSegment struct {
	Link
	LowMS  float64 `json:"low_ms"`
	HighMS float64 `json:"high_ms"`
}

type RoundChanges struct {
	HopTTLs         []int  `json:"hop_ttls,omitempty"`
	OriginTTLs      []int  `json:"origin_ttls,omitempty"`
	LatencySegments []Link `json:"latency_segments,omitempty"`
}

func (c RoundChanges) Empty() bool {
	return len(c.HopTTLs)+len(c.OriginTTLs)+len(c.LatencySegments) == 0
}

// NewChangeRound uses full-visibility discoveries that reached the same
// resolved destination. Blank hops and destination-only traces do not supply
// evidence of a change. origin is a lookup against an existing local index.
func NewChangeRound(p *Path, origin func(netip.Addr) uint32) (ChangeRound, bool) {
	if p == nil || !p.DestinationReached || p.MeasurementFidelity == nil || p.MeasurementFidelity.Version != 1 ||
		p.MeasurementFidelity.HopVisibility != "full" || p.Vantage == "" || p.TraceCount < 1 || p.TraceCount > 16 ||
		len(p.Hops) > 64 || len(p.Links) > maxChangeObservations {
		return ChangeRound{}, false
	}
	target, err := netip.ParseAddr(p.TargetIP)
	if err != nil || target.Zone() != "" {
		return ChangeRound{}, false
	}
	round := ChangeRound{TargetIP: target.Unmap().String(), Vantage: p.Vantage, Fidelity: *p.MeasurementFidelity, TraceCount: p.TraceCount}
	nodes := make(map[int]map[string]HopNode, len(p.Hops))
	for _, hop := range p.Hops {
		if hop.TTL < 1 || hop.TTL > 64 || len(hop.Nodes) > p.TraceCount || nodes[hop.TTL] != nil {
			return ChangeRound{}, false
		}
		nodes[hop.TTL] = make(map[string]HopNode, len(hop.Nodes))
		observed := ChangeHop{TTL: hop.TTL}
		completeOrigins := origin != nil
		for _, node := range hop.Nodes {
			address, err := netip.ParseAddr(node.IP)
			if node.Received < 1 || err != nil || address.Zone() != "" || address.Unmap().String() != node.IP {
				continue
			}
			if _, duplicate := nodes[hop.TTL][node.IP]; duplicate {
				return ChangeRound{}, false
			}
			nodes[hop.TTL][node.IP] = node
			observed.Responders = append(observed.Responders, node.IP)
			if origin != nil {
				asn := origin(address)
				completeOrigins = completeOrigins && asn != 0
				observed.Origins = append(observed.Origins, asn)
			}
		}
		if len(observed.Responders) == 0 {
			continue
		}
		if completeOrigins {
			observed.Origins = sortedDistinct(observed.Origins)
		} else {
			observed.Origins = nil
		}
		sort.Strings(observed.Responders)
		round.Hops = append(round.Hops, observed)
	}
	if len(round.Hops) == 0 {
		return ChangeRound{}, false
	}
	sort.Slice(round.Hops, func(i, j int) bool { return round.Hops[i].TTL < round.Hops[j].TTL })
	for _, link := range p.Links {
		from, to := nodes[link.TTL], nodes[link.TTL+1]
		// An RTT envelope aggregated across several ECMP branches cannot be
		// attributed to an individual adjacency without per-flow timings.
		if len(from) != 1 || len(to) != 1 {
			continue
		}
		left, right := from[link.From], to[link.To]
		if !validChangeRTT(left) || !validChangeRTT(right) {
			continue
		}
		round.Segments = append(round.Segments, ChangeSegment{Link: link,
			LowMS: right.RTTMinMs - left.RTTMaxMs, HighMS: right.RTTMaxMs - left.RTTMinMs})
	}
	return round, true
}

func sortedDistinct(values []uint32) []uint32 {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func validChangeRTT(n HopNode) bool {
	return n.Received > 0 && n.RTTMinMs > 0 && n.RTTMaxMs >= n.RTTMinMs && !math.IsInf(n.RTTMaxMs, 0)
}

// Comparable reports whether two rounds use the same observation method and
// destination. Callers also enforce the test and vantage's current authority.
func (before ChangeRound) Comparable(after ChangeRound) bool {
	return before.TargetIP == after.TargetIP && before.TargetIP != "" && before.Vantage == after.Vantage &&
		before.TraceCount == after.TraceCount && before.Fidelity == after.Fidelity
}

// ConfirmChanges compares an established round with two subsequent rounds.
// An unresponsive TTL or a known ECMP alternative cannot establish a hop or
// origin change. An RTT shift must recur in both rounds on the same adjacency.
func ConfirmChanges(before, first, latest ChangeRound, minimumLatencyMS float64) RoundChanges {
	var changes RoundChanges
	if !before.Comparable(first) || !before.Comparable(latest) {
		return changes
	}
	initial := make(map[int]ChangeHop, len(before.Hops))
	candidate := make(map[int]ChangeHop, len(first.Hops))
	for _, hop := range before.Hops {
		initial[hop.TTL] = hop
	}
	for _, hop := range first.Hops {
		candidate[hop.TTL] = hop
	}
	for _, hop := range latest.Hops {
		old, seen := initial[hop.TTL], candidate[hop.TTL]
		if replacementConfirmed(old.Responders, seen.Responders, hop.Responders) {
			changes.HopTTLs = append(changes.HopTTLs, hop.TTL)
		}
		if replacementConfirmed(old.Origins, seen.Origins, hop.Origins) {
			changes.OriginTTLs = append(changes.OriginTTLs, hop.TTL)
		}
	}
	oldSegments, firstSegments := indexChangeSegments(before.Segments), indexChangeSegments(first.Segments)
	for _, segment := range latest.Segments {
		old, oldOK := oldSegments[segment.Link]
		seen, seenOK := firstSegments[segment.Link]
		if oldOK && seenOK && sustainedShift(old, seen, segment, minimumLatencyMS) {
			changes.LatencySegments = append(changes.LatencySegments, segment.Link)
		}
	}
	return changes
}

func replacementConfirmed[T comparable](before, candidate, latest []T) bool {
	return len(before) != 0 && overlaps(candidate, latest) && !overlaps(before, candidate) && !overlaps(before, latest)
}

func overlaps[T comparable](left, right []T) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func indexChangeSegments(segments []ChangeSegment) map[Link]ChangeSegment {
	byLink := make(map[Link]ChangeSegment, len(segments))
	for _, segment := range segments {
		byLink[segment.Link] = segment
	}
	return byLink
}

func sustainedShift(before, first, latest ChangeSegment, minimumLatencyMS float64) bool {
	// Require a separation of both the chosen floor and 50% of the envelope,
	// in the same direction, across two independent rounds.
	threshold := math.Max(minimumLatencyMS, math.Max(math.Abs(before.LowMS), math.Abs(before.HighMS))*0.5)
	return math.Min(first.LowMS, latest.LowMS)-before.HighMS >= threshold ||
		before.LowMS-math.Max(first.HighMS, latest.HighMS) >= threshold
}
