// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "slices"

// ASPathFacts describe one already validated AS path without interpreting
// unordered sets or confederations as ordered external hops.
type ASPathFacts struct {
	Length          int64    `json:"selection_length"`
	PossibleOrigins []uint32 `json:"possible_origins"`
	OriginAmbiguous bool     `json:"origin_ambiguous"`
	Upstream        uint32   `json:"upstream_asn,omitempty"`
}

func SummarizeASPath(path []ASPathSegment) ASPathFacts {
	origins := observedASPathOrigins(path)
	facts := ASPathFacts{Length: asPathSelectionLength(path), PossibleOrigins: origins.values, OriginAmbiguous: origins.unknown}
	if facts.PossibleOrigins == nil {
		facts.PossibleOrigins = []uint32{}
	}
	slices.Sort(facts.PossibleOrigins)
	if !facts.OriginAmbiguous {
		facts.Upstream = originUpstream(path, facts.PossibleOrigins[0])
	}
	return facts
}

func originUpstream(path []ASPathSegment, origin uint32) uint32 {
	started := false
	for segmentIndex := len(path) - 1; segmentIndex >= 0; segmentIndex-- {
		segment := path[segmentIndex]
		if segment.Kind != ASPathSequence {
			if !started && (segment.Kind == ASPathConfedSequence || segment.Kind == ASPathConfedSet) {
				continue
			}
			return 0
		}
		for valueIndex := len(segment.Values) - 1; valueIndex >= 0; valueIndex-- {
			started = true
			value := segment.Values[valueIndex]
			switch value {
			case origin:
				continue
			case 0, 23456:
				return 0
			default:
				return value
			}
		}
	}
	return 0
}

// ASPathChanges compare two retained candidates inside one continuous
// source epoch. The storage projection owns inter-epoch coverage decisions.
type ASPathChanges struct {
	SegmentsChanged       bool `json:"segments_changed"`
	OriginChanged         bool `json:"origin_changed"`
	OriginEvidenceChanged bool `json:"origin_evidence_changed"`
	UpstreamChanged       bool `json:"upstream_changed"`
	LengthChanged         bool `json:"length_changed"`
}

func CompareASPaths(before, after []ASPathSegment) ASPathChanges {
	previous, current := SummarizeASPath(before), SummarizeASPath(after)
	originsDiffer := previous.OriginAmbiguous != current.OriginAmbiguous || !slices.Equal(previous.PossibleOrigins, current.PossibleOrigins)
	definiteOrigins := !previous.OriginAmbiguous && !current.OriginAmbiguous
	return ASPathChanges{
		SegmentsChanged:       !slices.EqualFunc(before, after, equalObservedASPathSegment),
		OriginChanged:         originsDiffer && definiteOrigins,
		OriginEvidenceChanged: originsDiffer && !definiteOrigins,
		UpstreamChanged:       previous.Upstream != 0 && current.Upstream != 0 && previous.Upstream != current.Upstream,
		LengthChanged:         previous.Length != current.Length,
	}
}

func equalObservedASPathSegment(left, right ASPathSegment) bool {
	if left.Kind != right.Kind || len(left.Values) != len(right.Values) {
		return false
	}
	if slices.Equal(left.Values, right.Values) {
		return true
	}
	if left.Kind != ASPathSet && left.Kind != ASPathConfedSet {
		return false
	}
	// A wire segment has at most 255 original ASNs. Preserve their stored
	// order and compare set membership on owned, bounded copies.
	previous, current := slices.Clone(left.Values), slices.Clone(right.Values)
	slices.Sort(previous)
	slices.Sort(current)
	return slices.Equal(previous, current)
}
