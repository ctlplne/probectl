// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "bytes"

// parseBMPRouteNextHopAFI validates a unicast MP_REACH next-hop encoding
// against complete source OPENs. RFC8950's wire lengths select from allowed
// encodings; IPv4 NLRI with an IPv6 next hop additionally requires the actual
// receiving peer's advertised capability. Sender support cannot replace it.
// MP participation is explicit even for legacy IPv4. These payload facts do
// not establish tenant/router ownership, source credentials or a live epoch.
func parseBMPRouteNextHopAFI(sentOpen, receivedOpen []byte, view BMPRouteView, family RouteFamily, nextHopLength int, profiles ...RoutingSourceProfile) (uint16, error) {
	profile, err := routingSourceProfile(profiles)
	if err != nil || profile.Format != "" && view != BMPLocRIB {
		return 0, ErrRouteCapabilities
	}
	sent, err := parseRouteOpenCapabilities(sentOpen, profile)
	if err != nil {
		return 0, err
	}
	received, err := parseRouteOpenCapabilities(receivedOpen, profile)
	if err != nil {
		return 0, err
	}
	if family.SAFI != 1 || family.AFI != 1 && family.AFI != 2 || !sent.mpFamilies[family] || !received.mpFamilies[family] {
		return 0, ErrRouteCapabilities
	}
	var receiver routeOpenCapabilities
	switch view {
	case BMPAdjRIBInPrePolicy, BMPAdjRIBInPostPolicy:
		receiver = sent
	case BMPAdjRIBOutPrePolicy, BMPAdjRIBOutPostPolicy:
		receiver = received
	case BMPLocRIB:
		if !sent.fourAS || !bytes.Equal(sentOpen, receivedOpen) {
			return 0, ErrRouteCapabilities
		}
		receiver = sent
	default:
		return 0, ErrRouteCapabilities
	}
	switch nextHopLength {
	case 4:
		if family.AFI == 1 {
			return 1, nil
		}
	case 16, 32:
		if family.AFI == 2 {
			return 2, nil
		}
		key := routeNextHopCapability{NLRI: family, NextHopAFI: 2}
		if !receiver.nextHops[key] {
			return 0, ErrRouteCapabilities
		}
		return 2, nil
	}
	return 0, ErrRouteCapabilities
}
