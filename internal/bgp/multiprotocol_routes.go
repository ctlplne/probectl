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
	"net/netip"
)

// MultiprotocolReach retains explicit NLRI and next-hop families; it does not
// establish current source authority or infer any next-hop AS number.
type MultiprotocolReach struct {
	Family     RouteFamily
	NextHopAFI uint16
	NextHops   []netip.Addr
	Prefixes   []RoutePrefix
}

// MultiprotocolWithdraw preserves the complete withdrawn prefix/path identities.
type MultiprotocolWithdraw struct {
	Family   RouteFamily
	Prefixes []RoutePrefix
}

// MultiprotocolBudget reserves 128 bytes for reachability metadata (64 for
// withdrawals), charges one full input pass and delegates complete prefix
// memory/work to RoutePrefixBudget. It bounds resources, not route population.
type MultiprotocolBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrMPRouteAttributes = errors.New("bgp: malformed or unsupported multiprotocol unicast attributes")
	ErrMPRouteBudget     = errors.New("bgp: multiprotocol operation admission exceeded")
)

// parseMPReachRoutes decodes a complete MP_REACH value for IPv4/IPv6 unicast.
// The source session must explicitly establish ADD-PATH and next-hop encoding,
// including RFC8950 capability for IPv4 NLRI with an IPv6 next hop. Neither is
// guessed from packet length. Next-hop addresses are not next-hop AS numbers.
func parseMPReachRoutes(ctx context.Context, value []byte, nextHopAFI uint16, addPath bool, budget MultiprotocolBudget) (MultiprotocolReach, error) {
	none := MultiprotocolReach{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 128 || budget.WorkUnits <= int64(len(value)) {
		return none, ErrMPRouteBudget
	}
	if len(value) < 5 {
		return none, ErrMPRouteAttributes
	}
	family := RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[2]}
	if family.SAFI != 1 || family.AFI != 1 && family.AFI != 2 || family.AFI == 2 && nextHopAFI != 2 {
		return none, ErrMPRouteAttributes
	}
	length := int(value[3])
	if length > len(value)-5 {
		return none, ErrMPRouteAttributes
	}
	var hops [2]netip.Addr
	count := 1
	switch nextHopAFI {
	case 1:
		if length != 4 {
			return none, ErrMPRouteAttributes
		}
		hops[0] = netip.AddrFrom4([4]byte(value[4:8]))
	case 2:
		if length != 16 && length != 32 {
			return none, ErrMPRouteAttributes
		}
		hops[0] = netip.AddrFrom16([16]byte(value[4:20]))
		if length == 32 {
			hops[1] = netip.AddrFrom16([16]byte(value[20:36]))
			if !hops[1].IsLinkLocalUnicast() {
				return none, ErrMPRouteAttributes
			}
			count = 2
		}
	default:
		return none, ErrMPRouteAttributes
	}
	// RFC4760's reserved octet is ignored, not treated as an SNPA count.
	prefixes, err := ParseBGPRoutePrefixes(ctx, value[5+length:], family.AFI, addPath, RoutePrefixBudget{MemoryBytes: budget.MemoryBytes - 128, WorkUnits: budget.WorkUnits - int64(len(value))})
	if err != nil {
		if errors.Is(err, ErrBGPRoutePrefixBudget) {
			return none, errors.Join(ErrMPRouteBudget, err)
		}
		return none, errors.Join(ErrMPRouteAttributes, err)
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return MultiprotocolReach{Family: family, NextHopAFI: nextHopAFI, NextHops: append([]netip.Addr(nil), hops[:count]...), Prefixes: prefixes}, nil
}

// parseMPUnreachRoutes decodes full MP_UNREACH unicast withdrawals. Empty
// prefixes alone do not prove synchronization: only the complete exclusive
// UPDATE marker can establish End-of-RIB for an authorized view/session.
func parseMPUnreachRoutes(ctx context.Context, value []byte, addPath bool, budget MultiprotocolBudget) (MultiprotocolWithdraw, error) {
	none := MultiprotocolWithdraw{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 64 || budget.WorkUnits <= int64(len(value)) {
		return none, ErrMPRouteBudget
	}
	if len(value) < 3 {
		return none, ErrMPRouteAttributes
	}
	family := RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[2]}
	if family.SAFI != 1 || family.AFI != 1 && family.AFI != 2 {
		return none, ErrMPRouteAttributes
	}
	prefixes, err := ParseBGPRoutePrefixes(ctx, value[3:], family.AFI, addPath, RoutePrefixBudget{MemoryBytes: budget.MemoryBytes - 64, WorkUnits: budget.WorkUnits - int64(len(value))})
	if err != nil {
		if errors.Is(err, ErrBGPRoutePrefixBudget) {
			return none, errors.Join(ErrMPRouteBudget, err)
		}
		return none, errors.Join(ErrMPRouteAttributes, err)
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return MultiprotocolWithdraw{Family: family, Prefixes: prefixes}, nil
}
