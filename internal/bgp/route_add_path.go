// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var ErrRouteCapabilities = errors.New("bgp: unavailable or inconsistent route capabilities")

type routeNextHopCapability struct {
	NLRI       RouteFamily
	NextHopAFI uint16
}

type routeOpenCapabilities struct {
	families   map[RouteFamily]bool
	mpFamilies map[RouteFamily]bool
	nextHops   map[routeNextHopCapability]bool
	addPath    map[RouteFamily]byte
	fourAS     bool
	asn        uint32
}

// parseBMPRouteAddPath derives NLRI encoding from both complete Peer Up OPENs.
// Adjacent views use RFC7911's direction-specific negotiation. RFC9069's
// fabricated Loc-RIB OPEN instead uses capability presence, regardless of its
// send/receive intent. An absent or malformed OPEN cannot authorize decoding.
//
// ASN wire width still comes from the BMP header, not these capabilities.
// These source-supplied bytes establish no tenant, router or current session.
func parseBMPRouteAddPath(sentOpen, receivedOpen []byte, view BMPRouteView, family RouteFamily) (bool, error) {
	sent, err := parseRouteOpenCapabilities(sentOpen)
	if err != nil {
		return false, err
	}
	received, err := parseRouteOpenCapabilities(receivedOpen)
	if err != nil {
		return false, err
	}
	if !sent.families[family] || !received.families[family] {
		return false, ErrRouteCapabilities
	}
	local, remote := sent.addPath[family], received.addPath[family]
	switch view {
	case BMPAdjRIBInPrePolicy, BMPAdjRIBInPostPolicy:
		return remote&2 != 0 && local&1 != 0, nil
	case BMPAdjRIBOutPrePolicy, BMPAdjRIBOutPostPolicy:
		return local&2 != 0 && remote&1 != 0, nil
	case BMPLocRIB:
		// RFC9069 requires the received OPEN to repeat the fabricated sent
		// OPEN, including its four-octet-AS capability and represented families.
		if !sent.fourAS || !bytes.Equal(sentOpen, receivedOpen) {
			return false, ErrRouteCapabilities
		}
		return local != 0, nil
	default:
		return false, ErrRouteCapabilities
	}
}

func parseRouteOpenCapabilities(raw []byte) (routeOpenCapabilities, error) {
	none := routeOpenCapabilities{}
	// RFC8654 does not extend OPENs: their protocol maximum remains 4096.
	// Both input and every allocation are therefore bounded by wire framing.
	if len(raw) < 29 || len(raw) > 4096 || raw[18] != 1 || raw[19] != 4 || int(binary.BigEndian.Uint16(raw[16:18])) != len(raw) {
		return none, ErrRouteCapabilities
	}
	for _, value := range raw[:16] {
		if value != 255 {
			return none, ErrRouteCapabilities
		}
	}
	optionalLength, offset, parameterHeader := int(raw[28]), 29, 2
	if optionalLength != 0 && len(raw) > offset && raw[offset] == 255 {
		if len(raw) < 32 {
			return none, ErrRouteCapabilities
		}
		// RFC9072 identifies extended encoding by the type sentinel; the
		// original one-byte length need not be 255 and is ignored here.
		optionalLength, offset, parameterHeader = int(binary.BigEndian.Uint16(raw[30:32])), 32, 3
	}
	if optionalLength != len(raw)-offset {
		return none, ErrRouteCapabilities
	}
	out := routeOpenCapabilities{
		families:   map[RouteFamily]bool{{AFI: 1, SAFI: 1}: true},
		addPath:    make(map[RouteFamily]byte),
		mpFamilies: make(map[RouteFamily]bool),
		nextHops:   make(map[routeNextHopCapability]bool),
	}
	seenAddPath := false
	for offset < len(raw) {
		if len(raw)-offset < parameterHeader {
			return none, ErrRouteCapabilities
		}
		kind, length := raw[offset], int(raw[offset+1])
		if parameterHeader == 3 {
			length = int(binary.BigEndian.Uint16(raw[offset+1 : offset+3]))
		}
		offset += parameterHeader
		if length > len(raw)-offset {
			return none, ErrRouteCapabilities
		}
		value := raw[offset : offset+length]
		offset += length
		if kind != 2 {
			continue
		}
		if err := out.parseCapabilities(value, &seenAddPath); err != nil {
			return none, err
		}
	}
	return out, nil
}

func (c *routeOpenCapabilities) parseCapabilities(raw []byte, seenAddPath *bool) error {
	for len(raw) != 0 {
		if len(raw) < 2 || int(raw[1]) > len(raw)-2 {
			return ErrRouteCapabilities
		}
		kind, length := raw[0], int(raw[1])
		value := raw[2 : 2+length]
		raw = raw[2+length:]
		switch kind {
		case 1: // RFC4760 multiprotocol capability; reserved octet ignored.
			if length != 4 {
				return ErrRouteCapabilities
			}
			family := RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[3]}
			c.families[family], c.mpFamilies[family] = true, true
		case 5: // RFC8950: NLRI AFI, two-byte SAFI, next-hop AFI.
			if length == 0 || length%6 != 0 {
				return ErrRouteCapabilities
			}
			for len(value) != 0 {
				safi := binary.BigEndian.Uint16(value[2:4])
				if safi <= 255 {
					key := routeNextHopCapability{NLRI: RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: uint8(safi)}, NextHopAFI: binary.BigEndian.Uint16(value[4:6])}
					c.nextHops[key] = true
				}
				value = value[6:]
			}
		case 65: // RFC6793 four-octet-AS capability, never BMP wire width.
			if length != 4 {
				return ErrRouteCapabilities
			}
			asn := binary.BigEndian.Uint32(value)
			if c.fourAS && c.asn != asn {
				return ErrRouteCapabilities
			}
			c.fourAS, c.asn = true, asn
		case 69:
			// RFC7911 requires one instance containing all family tuples.
			// Unsupported intent or conflicting repeated tuples leave source
			// encoding unknown; never infer ordinary NLRI from that ambiguity.
			if *seenAddPath || length == 0 || length%4 != 0 {
				return ErrRouteCapabilities
			}
			*seenAddPath = true
			for len(value) != 0 {
				family := RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[2]}
				mode := value[3]
				if mode < 1 || mode > 3 || c.addPath[family] != 0 && c.addPath[family] != mode {
					return ErrRouteCapabilities
				}
				c.addPath[family] = mode
				value = value[4:]
			}
		}
	}
	return nil
}
