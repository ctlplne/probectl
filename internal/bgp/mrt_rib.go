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

// MRTRIBRecord is one complete source record, never whole-source completion.
// Entries refer to the original verified peer table by index. Public paths
// carry no BMP OPEN, router identity, session capability or forwarding claim.
type MRTRIBRecord struct {
	ObservedUnixNanos int64
	Sequence          uint32
	Family            RouteFamily
	Entries           []MRTRIBEntry
}

type MRTRIBEntry struct {
	PeerIndex           uint16
	OriginatedUnixNanos int64
	Route               RoutePrefix
	Attributes          []RouteAttribute
	Path                RouteASPath
	NextHops            []netip.Addr
}

// DecodeMRTRIB accepts RFC6396 IPv4/IPv6 unicast and generic records, including
// their RFC8050 ADD-PATH variants. ASN width comes from the MRT format (four
// octets), never a trial parse. Validate the complete record twice before any
// entry escapes; raw attributes retain original flags, order and values.
func DecodeMRTRIB(ctx context.Context, raw []byte, peerCount int, budget UpdateFrameBudget) (MRTRIBRecord, error) {
	timestamp, subtype, body, err := decodeMRTTableRecord(ctx, raw, budget)
	if err != nil {
		return MRTRIBRecord{}, errors.Join(ErrMRTRecord, err)
	}
	if peerCount < 0 || peerCount > 65535 {
		return MRTRIBRecord{}, ErrMRTRecord
	}
	if int64(len(raw)) > budget.MemoryBytes/512 || int64(len(raw)) > budget.WorkUnits/128 {
		return MRTRIBRecord{}, ErrMRTBudget
	}
	family, route, sequence, entries, count, addEntryPath, err := decodeMRTRIBHeader(ctx, subtype, body, budget)
	if err != nil {
		return MRTRIBRecord{}, errors.Join(ErrMRTRecord, err)
	}
	// The first pass checks every late path; the second retains owned output.
	if _, err := decodeMRTRIBEntries(ctx, entries, count, peerCount, family, route, addEntryPath, budget, false); err != nil {
		return MRTRIBRecord{}, errors.Join(ErrMRTRecord, err)
	}
	output, err := decodeMRTRIBEntries(ctx, entries, count, peerCount, family, route, addEntryPath, budget, true)
	if err != nil {
		return MRTRIBRecord{}, errors.Join(ErrMRTRecord, err)
	}
	return MRTRIBRecord{ObservedUnixNanos: timestamp, Sequence: sequence, Family: family, Entries: output}, nil
}

func decodeMRTRIBHeader(ctx context.Context, subtype uint16, body []byte, budget UpdateFrameBudget) (RouteFamily, RoutePrefix, uint32, []byte, int, bool, error) {
	none := func() (RouteFamily, RoutePrefix, uint32, []byte, int, bool, error) {
		return RouteFamily{}, RoutePrefix{}, 0, nil, 0, false, ErrMRTRecord
	}
	if len(body) < 7 {
		return none()
	}
	sequence := binary.BigEndian.Uint32(body[:4])
	body = body[4:]
	family := RouteFamily{SAFI: 1}
	addEntryPath, addPrefixPath := false, false
	switch subtype {
	case 2, 8:
		family.AFI = 1
		addEntryPath = subtype == 8
	case 4, 10:
		family.AFI = 2
		addEntryPath = subtype == 10
	case 6, 12:
		if len(body) < 4 {
			return none()
		}
		family.AFI, family.SAFI = binary.BigEndian.Uint16(body[:2]), body[2]
		body = body[3:]
		addPrefixPath = subtype == 12
	default:
		return none()
	}
	if family.SAFI != 1 || family.AFI != 1 && family.AFI != 2 {
		return none()
	}
	offset := 0
	if addPrefixPath {
		offset = 4
	}
	if len(body) <= offset {
		return none()
	}
	length := offset + 1 + (int(body[offset])+7)/8
	if length > len(body)-2 {
		return none()
	}
	prefixes, err := ParseBGPRoutePrefixes(ctx, body[:length], family.AFI, addPrefixPath, RoutePrefixBudget(budget))
	if err != nil {
		return RouteFamily{}, RoutePrefix{}, 0, nil, 0, false, err
	}
	if len(prefixes) != 1 {
		return none()
	}
	count := int(binary.BigEndian.Uint16(body[length : length+2]))
	return family, prefixes[0], sequence, body[length+2:], count, addEntryPath, nil
}

func decodeMRTRIBEntries(ctx context.Context, raw []byte, count, peerCount int, family RouteFamily, route RoutePrefix, addPath bool, budget UpdateFrameBudget, retain bool) ([]MRTRIBEntry, error) {
	var output []MRTRIBEntry
	minimum := 8
	if addPath {
		minimum += 4
	}
	if count > len(raw)/minimum {
		return nil, ErrMRTRecord
	}
	if retain {
		output = make([]MRTRIBEntry, 0, count)
	}
	for range count {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(raw) < minimum {
			return nil, ErrMRTRecord
		}
		entry := MRTRIBEntry{PeerIndex: binary.BigEndian.Uint16(raw[:2]), OriginatedUnixNanos: int64(binary.BigEndian.Uint32(raw[2:6])) * 1_000_000_000, Route: route}
		if int(entry.PeerIndex) >= peerCount {
			return nil, ErrMRTRecord
		}
		if addPath {
			entry.Route.HasPathID = true
			entry.Route.PathID = binary.BigEndian.Uint32(raw[6:10])
		}
		length := int(binary.BigEndian.Uint16(raw[minimum-2 : minimum]))
		if length > len(raw)-minimum {
			return nil, ErrMRTRecord
		}
		part := UpdateFrameBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.WorkUnits / 4}
		var err error
		entry.Attributes, err = ParseBGPRouteAttributes(ctx, raw[minimum:minimum+length], RouteAttributeBudget(part))
		if err != nil {
			return nil, err
		}
		if err := validateSourceRouteAttributes(entry.Attributes); err != nil {
			return nil, err
		}
		if !sourceHasOrigin(entry.Attributes) {
			return nil, ErrMRTRecord
		}
		entry.Path, err = reconstructRouteASPath(ctx, entry.Attributes, 4, ASPathParseBudget(part))
		if err != nil {
			return nil, err
		}
		entry.NextHops, err = decodeMRTNextHops(entry.Attributes, family)
		if err != nil {
			return nil, err
		}
		if retain {
			output = append(output, entry)
		}
		raw = raw[minimum+length:]
	}
	if len(raw) != 0 {
		return nil, ErrMRTRecord
	}
	return output, nil
}

func decodeMRTNextHops(attributes []RouteAttribute, family RouteFamily) ([]netip.Addr, error) {
	var legacy, multiprotocol []netip.Addr
	for _, attribute := range attributes {
		switch attribute.Type {
		case 3:
			if len(attribute.Value) != 4 {
				return nil, ErrMRTRecord
			}
			legacy = []netip.Addr{netip.AddrFrom4([4]byte(attribute.Value))}
		case 14:
			value := attribute.Value
			// RFC6396 §4.3.4 removes AFI/SAFI, reserved and NLRI here.
			if len(value) == 0 || int(value[0]) != len(value)-1 {
				return nil, ErrMRTRecord
			}
			switch value[0] {
			case 4:
				if family.AFI != 1 {
					return nil, ErrMRTRecord
				}
				multiprotocol = []netip.Addr{netip.AddrFrom4([4]byte(value[1:]))}
			case 16, 32:
				multiprotocol = []netip.Addr{netip.AddrFrom16([16]byte(value[1:17]))}
				if value[0] == 32 {
					link := netip.AddrFrom16([16]byte(value[17:33]))
					if !link.IsLinkLocalUnicast() {
						return nil, ErrMRTRecord
					}
					multiprotocol = append(multiprotocol, link)
				}
			default:
				return nil, ErrMRTRecord
			}
		case 15:
			return nil, ErrMRTRecord
		}
	}
	if len(multiprotocol) != 0 {
		return multiprotocol, nil
	}
	if family.AFI == 1 && len(legacy) != 0 {
		return legacy, nil
	}
	return nil, ErrMRTRecord
}
