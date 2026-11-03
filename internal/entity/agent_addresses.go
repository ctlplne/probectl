// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net/netip"
	"sort"
)

// MaxAgentAddressSnapshotBytes reuses the evidence client's existing message
// bound. Overflow refuses the complete snapshot; it never truncates facts.
const MaxAgentAddressSnapshotBytes = 1 << 20

var agentLimitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// NormalizeAgentAddresses keeps nil legacy/withheld distinct from an explicit
// empty complete snapshot. Addresses are observations, never dial targets or
// identity aliases, so loopback/private/link-local unicast remains meaningful.
func NormalizeAgentAddresses(values []netip.Addr) ([]netip.Addr, error) {
	if values == nil {
		return nil, nil
	}
	out := make([]netip.Addr, 0, len(values))
	seen := map[netip.Addr]bool{}
	bytes := 2
	for _, raw := range values {
		address := raw.Unmap()
		if !address.IsValid() || raw.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address == agentLimitedBroadcast {
			return nil, ErrInvalidClaim
		}
		bytes += len(address.String()) + 3
		if bytes > MaxAgentAddressSnapshotBytes {
			return nil, ErrInvalidClaim
		}
		if !seen[address] {
			seen[address] = true
			out = append(out, address)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// ParseAgentAddressSnapshot is called only for a present protobuf message.
// Even a nil repeated field therefore means a complete empty snapshot.
func ParseAgentAddressSnapshot(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	bytes := 2
	for _, value := range values {
		bytes += len(value) + 3
		if bytes > MaxAgentAddressSnapshotBytes {
			return nil, ErrInvalidClaim
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, ErrInvalidClaim
		}
		out = append(out, address)
	}
	return NormalizeAgentAddresses(out)
}
