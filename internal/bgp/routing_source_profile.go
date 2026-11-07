// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

// RoutingSourceFRRLocRIBV1 describes FRR's selected-RIB serializer, not a BGP
// negotiation. Its peer_self OPEN may contain an empty ADD-PATH capability and
// omit monitored MP families. The serializer removes ADD-PATH/ENHE and emits
// ordinary IPv4 NLRI or MP IPv6 NLRI. Keep the original OPENs, never repair them.
const RoutingSourceFRRLocRIBV1 = "frr_loc_rib_v1"

// RoutingSourceProfile is operator configuration, never a field supplied by a
// BMP packet. The zero value keeps strict RFC capability validation. A stored
// profile must be authorized by the current source binding before use.
type RoutingSourceProfile struct {
	Format   string
	Families []RouteFamily
}

func routingSourceProfile(profiles []RoutingSourceProfile) (RoutingSourceProfile, error) {
	if len(profiles) == 0 {
		return RoutingSourceProfile{}, nil
	}
	if len(profiles) != 1 {
		return RoutingSourceProfile{}, ErrRouteCapabilities
	}
	profile := profiles[0]
	if profile.Format == "" && len(profile.Families) == 0 {
		return RoutingSourceProfile{}, nil
	}
	if profile.Format != RoutingSourceFRRLocRIBV1 || len(profile.Families) == 0 || len(profile.Families) > 2 {
		return RoutingSourceProfile{}, ErrRouteCapabilities
	}
	var seen [3]bool
	for _, family := range profile.Families {
		if family.SAFI != 1 || family.AFI < 1 || family.AFI > 2 || seen[family.AFI] {
			return RoutingSourceProfile{}, ErrRouteCapabilities
		}
		seen[family.AFI] = true
	}
	profile.Families = make([]RouteFamily, 0, len(profile.Families))
	for afi := uint16(1); afi <= 2; afi++ {
		if seen[afi] {
			profile.Families = append(profile.Families, RouteFamily{AFI: afi, SAFI: 1})
		}
	}
	return profile, nil
}

func (profile RoutingSourceProfile) applyFRRFamilies(capabilities *routeOpenCapabilities) {
	capabilities.families = make(map[RouteFamily]bool)
	capabilities.mpFamilies = make(map[RouteFamily]bool)
	capabilities.nextHops = make(map[routeNextHopCapability]bool)
	for _, family := range profile.Families {
		capabilities.families[family] = true
		if family.AFI == 2 {
			capabilities.mpFamilies[family] = true
		}
	}
}
