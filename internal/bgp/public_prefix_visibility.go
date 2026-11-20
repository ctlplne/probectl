// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"time"
)

type PublicVisibilityPeer struct {
	Address netip.Addr
	ASN     uint32
}

type PublicVisibilityOrigin struct {
	ASN   uint32 `json:"asn"`
	Peers int    `json:"peers"`
}

type PublicPrefixVisibility struct {
	Prefix         netip.Prefix             `json:"prefix"`
	From           time.Time                `json:"from"`
	Through        time.Time                `json:"through"`
	Available      bool                     `json:"available"`
	Availability   string                   `json:"availability"`
	EligiblePeers  int                      `json:"eligible_peers"`
	VisiblePeers   int                      `json:"visible_peers"`
	AmbiguousPeers int                      `json:"ambiguous_origin_peers"`
	Origins        []PublicVisibilityOrigin `json:"origins"`
}

type publicVisibilityOriginSet struct {
	values  []uint32
	unknown bool
}

type PrefixVisibilityProjection struct {
	prefix     netip.Prefix
	from       time.Time
	through    time.Time
	population int
	continuous bool
	failure    string
	active     map[PublicVisibilityPeer]map[RoutePrefix]publicVisibilityOriginSet
}

var ErrPublicVisibilityBaseline = errors.New("bgp: unusable prefix visibility baseline")

func newPrefixVisibilityProjection(prefix netip.Prefix, at time.Time, population int) *PrefixVisibilityProjection {
	return &PrefixVisibilityProjection{prefix: prefix, from: at.UTC(), through: at.UTC(), continuous: true,
		population: population, active: make(map[PublicVisibilityPeer]map[RoutePrefix]publicVisibilityOriginSet)}
}

func (p *PrefixVisibilityProjection) disrupt(reason string) {
	if p.continuous {
		p.continuous = false
		p.failure = reason
	}
}

func (p *PrefixVisibilityProjection) retain(peer PublicVisibilityPeer, route RoutePrefix, origin publicVisibilityOriginSet) {
	if p.active[peer] == nil {
		p.active[peer] = make(map[RoutePrefix]publicVisibilityOriginSet)
	}
	p.active[peer][route] = origin
}

func publicVisibilityOrigins(path RouteASPath) publicVisibilityOriginSet {
	return observedASPathOrigins(path.Path.Segments)
}

func observedASPathOrigins(path []ASPathSegment) publicVisibilityOriginSet {
	for index := len(path) - 1; index >= 0; index-- {
		segment := path[index]
		values := segment.Values
		if segment.Kind == ASPathSequence && len(values) > 0 {
			asn := values[len(values)-1]
			if asn > 0 && asn != 23456 {
				return publicVisibilityOriginSet{values: []uint32{asn}}
			}
			break
		}
		if segment.Kind == ASPathSet {
			out := publicVisibilityOriginSet{unknown: true}
			for _, asn := range values {
				if asn > 0 && asn != 23456 && !slices.Contains(out.values, asn) {
					out.values = append(out.values, asn)
				}
			}
			return out
		}
	}
	return publicVisibilityOriginSet{unknown: true}
}

func (p *PrefixVisibilityProjection) Point() PublicPrefixVisibility {
	out := PublicPrefixVisibility{Prefix: p.prefix, From: p.from, Through: p.through,
		Available: p.continuous && p.population > 0, Origins: []PublicVisibilityOrigin{}}
	if !out.Available {
		out.Availability = p.failure
		if out.Availability == "" {
			out.Availability = "empty_cohort"
		}
		return out
	}
	out.Availability = "available"
	out.EligiblePeers = p.population
	counts := map[uint32]int{}
	for _, routes := range p.active {
		if len(routes) == 0 {
			continue
		}
		out.VisiblePeers++
		peerOrigins := map[uint32]bool{}
		ambiguous := false
		for _, origin := range routes {
			ambiguous = ambiguous || origin.unknown
			for _, asn := range origin.values {
				peerOrigins[asn] = true
			}
		}
		if ambiguous || len(peerOrigins) != 1 {
			out.AmbiguousPeers++
		}
		for asn := range peerOrigins {
			counts[asn]++
		}
	}
	for asn, count := range counts {
		out.Origins = append(out.Origins, PublicVisibilityOrigin{ASN: asn, Peers: count})
	}
	slices.SortFunc(out.Origins, func(a, b PublicVisibilityOrigin) int { return cmp.Compare(a.ASN, b.ASN) })
	return out
}
