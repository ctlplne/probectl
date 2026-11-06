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

// BGPRoutePrefix retains the complete unicast prefix and explicitly negotiated
// ADD-PATH identity. A path identifier of0 is distinct from absent ADD-PATH.
type BGPRoutePrefix struct {
	Prefix    netip.Prefix
	PathID    uint32
	HasPathID bool
}

// BGPRoutePrefixBudget charges64conservative bytes per retained prefix and
// both complete byte passes. It bounds resources, not logical row population.
type BGPRoutePrefixBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrBGPRoutePrefix       = errors.New("bgp: malformed or unsupported unicast prefix encoding")
	ErrBGPRoutePrefixBudget = errors.New("bgp: unicast prefix operation admission exceeded")
)

// ParseBGPRoutePrefixes decodes RFC4271/RFC4760 unicast NLRI or withdrawals
// with an explicit AFI and RFC7911 ADD-PATH mode. Capabilities come from the
// authenticated source, never a guess from these bytes. Empty NLRI is not, by
// itself, proof of End-of-RIB or complete initial synchronization.
func ParseBGPRoutePrefixes(ctx context.Context, raw []byte, afi uint16, addPath bool, budget BGPRoutePrefixBudget) ([]BGPRoutePrefix, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	maximum := 0
	switch afi {
	case 1:
		maximum = 32
	case 2:
		maximum = 128
	default:
		return nil, ErrBGPRoutePrefix
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.WorkUnits/2 {
		return nil, ErrBGPRoutePrefixBudget
	}
	count := 0
	for pos := 0; pos < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if addPath {
			if len(raw)-pos < 4 {
				return nil, ErrBGPRoutePrefix
			}
			pos += 4
		}
		if pos == len(raw) {
			return nil, ErrBGPRoutePrefix
		}
		bits := int(raw[pos])
		pos++
		if bits > maximum {
			return nil, ErrBGPRoutePrefix
		}
		octets := (bits + 7) / 8
		if octets > len(raw)-pos {
			return nil, ErrBGPRoutePrefix
		}
		pos += octets
		count++
	}
	if int64(count) > budget.MemoryBytes/64 {
		return nil, ErrBGPRoutePrefixBudget
	}
	output := make([]BGPRoutePrefix, 0, count)
	for pos := 0; pos < len(raw); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		route := BGPRoutePrefix{HasPathID: addPath}
		if addPath {
			route.PathID = binary.BigEndian.Uint32(raw[pos : pos+4])
			pos += 4
		}
		bits := int(raw[pos])
		pos++
		octets := (bits + 7) / 8
		var ip netip.Addr
		if afi == 1 {
			var address [4]byte
			copy(address[:], raw[pos:pos+octets])
			ip = netip.AddrFrom4(address)
		} else {
			var address [16]byte
			copy(address[:], raw[pos:pos+octets])
			ip = netip.AddrFrom16(address)
		}
		// RFC4271 declares octet-padding bits irrelevant. Normalize them,
		// preserve the family, and never silently drop an entire prefix.
		route.Prefix = netip.PrefixFrom(ip, bits).Masked()
		output = append(output, route)
		pos += octets
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output, nil
}
