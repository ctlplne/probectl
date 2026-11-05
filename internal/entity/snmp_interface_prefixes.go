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

// MaxSNMPInterfacePrefixWireBytes shares the existing evidence request bound.
// It is not a prefix-count quota. The complete request, including its other
// fields and protobuf framing, is admitted separately by sender and receiver.
const MaxSNMPInterfacePrefixWireBytes = 1 << 20

// SNMPInterfacePrefix is untrusted complete-set metadata on one configured
// device observation. Neither ifIndex nor an address selects a canonical
// interface, router, routing context or tenant.
type SNMPInterfacePrefix struct {
	IfIndex uint32       `json:"if_index"`
	Prefix  netip.Prefix `json:"prefix"`
	OnLink  bool         `json:"on_link"`
}

// NormalizeSNMPInterfacePrefixes owns and orders the entire supported snapshot.
// Nil means unavailable/legacy. An empty walk cannot prove MIB support, so it
// cannot clear a previous set. Duplicate or invalid rows refuse the whole set.
func NormalizeSNMPInterfacePrefixes(rows []SNMPInterfacePrefix) ([]SNMPInterfacePrefix, error) {
	if rows == nil {
		return nil, nil
	}
	if len(rows) == 0 {
		return nil, ErrInvalidClaim
	}
	type key struct {
		index  uint32
		prefix netip.Prefix
	}
	seen := map[key]bool{}
	result := []SNMPInterfacePrefix{}
	used := 0
	for _, row := range rows {
		if row.IfIndex == 0 || row.IfIndex > 2147483647 || !row.Prefix.IsValid() || row.Prefix != row.Prefix.Masked() || row.Prefix.Addr().Is4In6() {
			return nil, ErrInvalidClaim
		}
		// Exact proto3 encoding of one positive ifIndex, prefix text and
		// optional true bit, including the repeated-message wrapper. Each
		// row is shorter than128 bytes, so its length prefix is one byte.
		width := 1
		for value := row.IfIndex; value >= 128; value >>= 7 {
			width++
		}
		cost := 5 + width + len(row.Prefix.String())
		if row.OnLink {
			cost += 2
		}
		if cost > MaxSNMPInterfacePrefixWireBytes-used {
			return nil, ErrInvalidClaim
		}
		used += cost
		k := key{row.IfIndex, row.Prefix}
		if seen[k] {
			return nil, ErrInvalidClaim
		}
		seen[k] = true
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IfIndex != result[j].IfIndex {
			return result[i].IfIndex < result[j].IfIndex
		}
		if compared := result[i].Prefix.Addr().Compare(result[j].Prefix.Addr()); compared != 0 {
			return compared < 0
		}
		return result[i].Prefix.Bits() < result[j].Prefix.Bits()
	})
	return result, nil
}
