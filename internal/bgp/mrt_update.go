// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
)

const (
	mrtBGP4MPType         = 16
	mrtBGP4MPExtendedType = 17
)

// MRTUpdate preserves the inbound collector peer, original timestamp and
// announced/withdrawn unicast paths. A session transition asks the receiver
// to re-establish coverage from a complete source before claiming visibility.
type MRTUpdate struct {
	ObservedUnixNanos int64
	PeerAddress       netip.Addr
	PeerASN           uint32
	OldState          uint16
	NewState          uint16
	Path              RouteASPath
	Groups            []RoutingChangeGroup
}

// StageMRTUpdates validates one original archive interval. The caller verifies
// that its source label, exact window and archive identity are contiguous
// with the preceding accepted interval before publishing staged changes.
func StageMRTUpdates(ctx context.Context, reader io.Reader, budget MRTArchiveBudget,
	stage func(context.Context, MRTUpdate) error) (int64, int64, error) {
	if reader == nil || stage == nil || !budget.valid() {
		return 0, 0, ErrMRTBudget
	}
	stream := mrtArchiveReader{source: reader, limits: budget}
	for {
		raw, err := stream.next(ctx)
		if err == io.EOF {
			return stream.bytes, stream.records, nil
		}
		if err != nil {
			return 0, 0, err
		}
		update, err := decodeMRTUpdate(ctx, raw, budget.Frame)
		if err != nil {
			return 0, 0, stream.recordError(raw, err)
		}
		if len(update.Groups) == 0 && update.NewState == 0 {
			continue
		}
		if err := stage(ctx, update); err != nil {
			return 0, 0, stream.recordError(raw, err)
		}
	}
}

type mrtUpdateFormat struct {
	asnWidth  int
	addPath   bool
	local     bool
	lifecycle bool
}

func mrtUpdateEncoding(subtype uint16) (mrtUpdateFormat, error) {
	switch subtype {
	case 0:
		return mrtUpdateFormat{asnWidth: 2, lifecycle: true}, nil
	case 5:
		return mrtUpdateFormat{asnWidth: 4, lifecycle: true}, nil
	case 1, 6, 8, 10:
		return mrtUpdateFormat{asnWidth: 2, local: subtype == 6 || subtype == 10, addPath: subtype == 8 || subtype == 10}, nil
	case 4, 7, 9, 11:
		return mrtUpdateFormat{asnWidth: 4, local: subtype == 7 || subtype == 11, addPath: subtype == 9 || subtype == 11}, nil
	default:
		return mrtUpdateFormat{}, ErrMRTRecord
	}
}

func decodeMRTUpdate(ctx context.Context, raw []byte, budget UpdateFrameBudget) (MRTUpdate, error) {
	out, format, body, err := mrtUpdatePeer(raw)
	if err != nil {
		return MRTUpdate{}, err
	}
	if format.lifecycle {
		if len(body) != 4 {
			return MRTUpdate{}, ErrMRTRecord
		}
		out.OldState, out.NewState = binary.BigEndian.Uint16(body[:2]), binary.BigEndian.Uint16(body[2:])
		if out.OldState < 1 || out.OldState > 6 || out.NewState < 1 || out.NewState > 6 {
			return MRTUpdate{}, ErrMRTRecord
		}
		return out, nil
	}
	if _, _, err := ParseBGPEndOfRIB(body); err != nil {
		return MRTUpdate{}, err
	}
	switch body[18] {
	case bgpMessageTypeUpdate:
		if !format.local {
			return decodeMRTUpdateRoutes(ctx, out, body, format, budget)
		}
	case 1, 3, 4, 5:
		// OPEN, NOTIFICATION, KEEPALIVE and ROUTE-REFRESH are not route
		// content. Session-state records carry the collector lifecycle.
	default:
		return MRTUpdate{}, ErrMRTRecord
	}
	return out, nil
}

func mrtUpdatePeer(raw []byte) (MRTUpdate, mrtUpdateFormat, []byte, error) {
	var out MRTUpdate
	var format mrtUpdateFormat
	if len(raw) < mrtCommonHeaderBytes || uint64(binary.BigEndian.Uint32(raw[8:12])) != uint64(len(raw)-mrtCommonHeaderBytes) {
		return out, format, nil, ErrMRTRecord
	}
	out.ObservedUnixNanos = int64(binary.BigEndian.Uint32(raw[:4])) * 1_000_000_000
	body := raw[mrtCommonHeaderBytes:]
	switch binary.BigEndian.Uint16(raw[4:6]) {
	case mrtBGP4MPType:
	case mrtBGP4MPExtendedType:
		if len(body) < 4 || binary.BigEndian.Uint32(body[:4]) >= 1_000_000 {
			return out, format, nil, ErrMRTRecord
		}
		out.ObservedUnixNanos += int64(binary.BigEndian.Uint32(body[:4])) * 1000
		body = body[4:]
	default:
		return out, format, nil, ErrMRTRecord
	}
	format, err := mrtUpdateEncoding(binary.BigEndian.Uint16(raw[6:8]))
	offset := format.asnWidth * 2
	if err != nil || len(body) < offset+4 || out.ObservedUnixNanos <= 0 {
		return out, format, nil, ErrMRTRecord
	}
	if format.asnWidth == 4 {
		out.PeerASN = binary.BigEndian.Uint32(body[:4])
	} else {
		out.PeerASN = uint32(binary.BigEndian.Uint16(body[:2]))
	}
	afi := binary.BigEndian.Uint16(body[offset+2 : offset+4])
	offset += 4
	size := 4
	if afi == 2 {
		size = 16
	} else if afi != 1 {
		return out, format, nil, ErrMRTRecord
	}
	if len(body) < offset+size*2 {
		return out, format, nil, ErrMRTRecord
	}
	out.PeerAddress, _ = netip.AddrFromSlice(body[offset : offset+size])
	return out, format, body[offset+size*2:], nil
}

func decodeMRTUpdateRoutes(ctx context.Context, out MRTUpdate, raw []byte, format mrtUpdateFormat, budget UpdateFrameBudget) (MRTUpdate, error) {
	frame, err := parseBGPUpdateFrame(ctx, raw, budget)
	if err != nil || frame.HasEndOfRIB {
		return out, err
	}
	if err := validateSourceRouteAttributes(frame.Attributes); err != nil {
		return MRTUpdate{}, err
	}
	prefixBudget := RoutePrefixBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.WorkUnits / 4}
	legacy := RoutingChangeGroup{Family: RouteFamily{AFI: 1, SAFI: 1}}
	legacy.Withdrawn, err = ParseBGPRoutePrefixes(ctx, frame.WithdrawnIPv4, 1, format.addPath, prefixBudget)
	if err != nil {
		return MRTUpdate{}, err
	}
	legacy.Announced, err = ParseBGPRoutePrefixes(ctx, frame.ReachableIPv4, 1, format.addPath, prefixBudget)
	if err != nil {
		return MRTUpdate{}, err
	}
	if len(legacy.Announced) > 0 {
		for _, attr := range frame.Attributes {
			if attr.Type == 3 {
				legacy.NextHops = []netip.Addr{netip.AddrFrom4([4]byte(attr.Value))}
			}
		}
		if len(legacy.NextHops) == 0 {
			return MRTUpdate{}, ErrMRTRecord
		}
	}
	if len(legacy.Announced)+len(legacy.Withdrawn) > 0 {
		out.Groups = append(out.Groups, legacy)
	}
	for _, attr := range frame.Attributes {
		if attr.Type != 14 && attr.Type != 15 {
			continue
		}
		group, err := mrtUpdateMultiprotocol(ctx, attr, format.addPath, MultiprotocolBudget(prefixBudget))
		if err != nil {
			return MRTUpdate{}, err
		}
		out.Groups = append(out.Groups, group)
	}
	for _, group := range out.Groups {
		if len(group.Announced) > 0 {
			if !sourceHasOrigin(frame.Attributes) {
				return MRTUpdate{}, ErrMRTRecord
			}
			out.Path, err = reconstructRouteASPath(ctx, frame.Attributes, format.asnWidth, ASPathParseBudget(prefixBudget))
			if err != nil {
				return MRTUpdate{}, err
			}
			break
		}
	}
	return out, ctx.Err()
}

func mrtUpdateMultiprotocol(ctx context.Context, attr RouteAttribute, addPath bool, budget MultiprotocolBudget) (RoutingChangeGroup, error) {
	if attr.Type == 15 {
		withdraw, err := parseMPUnreachRoutes(ctx, attr.Value, addPath, budget)
		return RoutingChangeGroup{Family: withdraw.Family, Withdrawn: withdraw.Prefixes}, err
	}
	if len(attr.Value) < 5 {
		return RoutingChangeGroup{}, ErrMRTRecord
	}
	// MRT encodes ADD-PATH explicitly in the subtype. The advertised
	// next-hop bytes describe observed wire encoding only; the archive has
	// no negotiated OPEN or canonical forwarding authority.
	nextHop := uint16(1)
	if attr.Value[3] == 16 || attr.Value[3] == 32 {
		nextHop = 2
	}
	reach, err := parseMPReachRoutes(ctx, attr.Value, nextHop, addPath, budget)
	return RoutingChangeGroup{Family: reach.Family, Announced: reach.Prefixes, NextHops: reach.NextHops}, err
}
