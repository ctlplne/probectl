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

var errBMPRouteChanges = errors.New("bgp: incomplete or inconsistent route changes")

// RoutingChanges retains complete wire attributes separately from the
// interpreted path. No peer ASN becomes a next-hop AS or origin, and no route
// view becomes a tenant/router grant or a claim about the forwarding table.
type RoutingChanges struct {
	Header     BMPRouteViewHeader
	Attributes []RouteAttribute
	Path       RouteASPath
	Groups     []RoutingChangeGroup
}

type RoutingChangeGroup struct {
	Family               RouteFamily
	Announced, Withdrawn []RoutePrefix
	NextHops             []netip.Addr
	EndOfRIB             bool
}

// DecodeRoutingChanges validates the whole source frame against retained,
// complete OPENs. It returns no partial paths on any refusal and grants no
// canonical source authority; the authenticated service supplies that boundary.
func DecodeRoutingChanges(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (RoutingChanges, error) {
	return decodeBMPRouteChanges(ctx, raw, peer, budget)
}

// decodeBMPRouteChanges composes source binding, negotiated encoding and the
// fields required for retained unicast paths. All groups validate before any
// result is returned. A receiver must invalidate the affected known generation
// on refusal; it must never keep old complete state after dropping this frame.
func decodeBMPRouteChanges(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (RoutingChanges, error) {
	none := RoutingChanges{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	// Reserve the complete pipeline, including repeated bounded OPEN parsing,
	// per-prefix descriptors, path reconstruction and owned attribute copies.
	weight := int64(len(raw)) + int64(len(peer.SentOpen)) + int64(len(peer.ReceivedOpen))
	if budget.MemoryBytes <= 8192 || budget.WorkUnits <= 8192 || weight > (budget.MemoryBytes-8192)/512 || weight > (budget.WorkUnits-8192)/64 {
		return none, ErrBGPUpdateFrameBudget
	}
	part := UpdateFrameBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.WorkUnits / 4}
	frame, err := parseBMPSourceRoute(ctx, raw, peer, part)
	if err != nil {
		return none, err
	}
	out := RoutingChanges{Header: frame.Header, Attributes: frame.Update.Attributes}
	if frame.Update.HasEndOfRIB {
		if _, err := parseBMPRouteAddPath(peer.SentOpen, peer.ReceivedOpen, frame.Header.View, frame.Update.EndOfRIB, peer.SourceProfile); err != nil {
			return none, err
		}
		out.Groups = []RoutingChangeGroup{{Family: frame.Update.EndOfRIB, EndOfRIB: true}}
		if err := ctx.Err(); err != nil {
			return none, err
		}
		return out, nil
	}
	return sourceUpdateChanges(ctx, frame, peer, part)
}

func sourceUpdateChanges(ctx context.Context, frame sourceRouteFrame, peer PeerUp, part UpdateFrameBudget) (RoutingChanges, error) {
	none := RoutingChanges{}
	out := RoutingChanges{Header: frame.Header, Attributes: frame.Update.Attributes}
	if err := validateSourceRouteAttributes(frame.Update.Attributes); err != nil {
		return none, err
	}
	legacy, err := sourceLegacyRouteChanges(ctx, frame, peer, part)
	if err != nil {
		return none, err
	}
	if len(legacy.Announced)+len(legacy.Withdrawn) > 0 {
		out.Groups = append(out.Groups, legacy)
	}
	for _, attr := range frame.Update.Attributes {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if attr.Type != 14 && attr.Type != 15 {
			continue
		}
		group, err := sourceMultiprotocolChanges(ctx, attr, frame.Header.View, peer, part)
		if err != nil {
			return none, err
		}
		out.Groups = append(out.Groups, group)
	}
	announces := false
	for _, group := range out.Groups {
		announces = announces || len(group.Announced) > 0
	}
	if announces {
		if !sourceHasOrigin(frame.Update.Attributes) {
			return none, errBMPRouteChanges
		}
		out.Path, err = reconstructRouteASPath(ctx, frame.Update.Attributes, frame.Header.ASNWidth, ASPathParseBudget(part))
		if err != nil {
			return none, err
		}
	}
	if len(out.Groups) == 0 {
		return none, errBMPRouteChanges
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}

func validateSourceRouteAttributes(attributes []RouteAttribute) error {
	var seen [256]bool
	for _, attr := range attributes {
		switch attr.Type {
		case 1, 2, 3, 4, 5, 6, 14, 15:
			if seen[attr.Type] {
				return errBMPRouteChanges
			}
			seen[attr.Type] = true
		}
		flags := attr.Flags & 0xe0
		switch attr.Type {
		case 1:
			if flags != 0x40 || len(attr.Value) != 1 || attr.Value[0] > 2 {
				return errBMPRouteChanges
			}
		case 2:
			if flags != 0x40 {
				return errBMPRouteChanges
			}
		case 3, 5:
			if flags != 0x40 || len(attr.Value) != 4 {
				return errBMPRouteChanges
			}
		case 6:
			if flags != 0x40 || len(attr.Value) != 0 {
				return errBMPRouteChanges
			}
		case 4:
			if flags != 0x80 || len(attr.Value) != 4 {
				return errBMPRouteChanges
			}
		case 14, 15:
			if flags != 0x80 {
				return errBMPRouteChanges
			}
		case 7, 17, 18:
			// The path decoder retains explicit RFC6793 discard provenance.
		default:
			if attr.Flags&0x80 == 0 {
				return errBMPRouteChanges
			}
		}
	}
	return nil
}

func sourceHasOrigin(attributes []RouteAttribute) bool {
	for _, attr := range attributes {
		if attr.Type == 1 {
			return true
		}
	}
	return false
}

func sourceLegacyRouteChanges(ctx context.Context, frame sourceRouteFrame, peer PeerUp, budget UpdateFrameBudget) (RoutingChangeGroup, error) {
	none := RoutingChangeGroup{}
	out := RoutingChangeGroup{Family: RouteFamily{AFI: 1, SAFI: 1}}
	if len(frame.Update.WithdrawnIPv4)+len(frame.Update.ReachableIPv4) == 0 {
		return out, nil
	}
	add, err := parseBMPRouteAddPath(peer.SentOpen, peer.ReceivedOpen, frame.Header.View, out.Family, peer.SourceProfile)
	if err != nil {
		return none, err
	}
	profile := RoutePrefixBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2}
	out.Withdrawn, err = ParseBGPRoutePrefixes(ctx, frame.Update.WithdrawnIPv4, 1, add, profile)
	if err != nil {
		return none, err
	}
	out.Announced, err = ParseBGPRoutePrefixes(ctx, frame.Update.ReachableIPv4, 1, add, profile)
	if err != nil {
		return none, err
	}
	if len(out.Announced) > 0 {
		for _, attr := range frame.Update.Attributes {
			if attr.Type == 3 {
				out.NextHops = []netip.Addr{netip.AddrFrom4([4]byte(attr.Value))}
			}
		}
		if len(out.NextHops) == 0 {
			return none, errBMPRouteChanges
		}
	}
	return out, nil
}

func sourceMultiprotocolChanges(ctx context.Context, attr RouteAttribute, view BMPRouteView, peer PeerUp, budget UpdateFrameBudget) (RoutingChangeGroup, error) {
	none := RoutingChangeGroup{}
	if len(attr.Value) < 3 {
		return none, errBMPRouteChanges
	}
	family := RouteFamily{AFI: binary.BigEndian.Uint16(attr.Value[:2]), SAFI: attr.Value[2]}
	add, err := parseBMPRouteAddPath(peer.SentOpen, peer.ReceivedOpen, view, family, peer.SourceProfile)
	if err != nil {
		return none, err
	}
	profile := MultiprotocolBudget(budget)
	if attr.Type == 15 {
		unreach, err := parseMPUnreachRoutes(ctx, attr.Value, add, profile)
		if err != nil {
			return none, err
		}
		if len(unreach.Prefixes) == 0 {
			return none, errBMPRouteChanges
		}
		return RoutingChangeGroup{Family: family, Withdrawn: unreach.Prefixes}, nil
	}
	if len(attr.Value) < 4 {
		return none, errBMPRouteChanges
	}
	nextAFI, err := parseBMPRouteNextHopAFI(peer.SentOpen, peer.ReceivedOpen, view, family, int(attr.Value[3]), peer.SourceProfile)
	if err != nil {
		return none, err
	}
	reach, err := parseMPReachRoutes(ctx, attr.Value, nextAFI, add, profile)
	if err != nil {
		return none, err
	}
	if len(reach.Prefixes) == 0 {
		return none, errBMPRouteChanges
	}
	return RoutingChangeGroup{Family: family, Announced: reach.Prefixes, NextHops: reach.NextHops}, nil
}
