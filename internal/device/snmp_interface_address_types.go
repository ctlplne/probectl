// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// RFC4293 ipAddressType shares the exact InetAddress index with IfIndex.
// Broadcast entries are network destinations, never owned interface addresses.
// Retain unicast and anycast without guessing from address or prefix bits.
const oidIPAddressType = ".1.3.6.1.2.1.4.34.1.4"

func snmpInterfaceAddressKey(row snmpInterfaceAddress) snmpInterfaceAddress {
	row.index = 0
	return row
}

func parseSNMPInterfaceAddressType(pdu gosnmp.SnmpPDU) (snmpInterfaceAddress, uint32, error) {
	suffix, ok := strings.CutPrefix(strings.TrimPrefix(pdu.Name, "."), strings.TrimPrefix(oidIPAddressType, ".")+".")
	kind, err := snmpAddressInterfaceIndex(pdu.Value)
	if !ok || err != nil || kind > 3 {
		return snmpInterfaceAddress{}, 0, errSNMPInterfacePrefixIncomplete
	}
	pdu.Name, pdu.Value = oidIPAddressIfIndex+"."+suffix, int(1)
	row, err := parseSNMPInterfaceAddress(pdu)
	if err != nil || kind == 3 && row.address.Is6() {
		return snmpInterfaceAddress{}, 0, errSNMPInterfacePrefixIncomplete
	}
	return snmpInterfaceAddressKey(row), kind, nil
}

func selectSNMPInterfaceAddressTypes(ctx context.Context, conn snmpInterfaceAddressWalker, rows []snmpInterfaceAddress, limits snmpInterfacePrefixLimits) ([]snmpInterfaceAddress, error) {
	types := make(map[snmpInterfaceAddress]uint32, len(rows))
	for _, row := range rows {
		types[snmpInterfaceAddressKey(row)] = 0
	}
	used := uint64(0)
	var refused error
	err := conn.walkInterfaceAddressTypes(ctx, func(pdu gosnmp.SnmpPDU) error {
		if refused != nil {
			return refused
		}
		refused = ctx.Err()
		if refused != nil {
			return refused
		}
		if uint64(len(pdu.Name)) > limits.IndexBytes-used {
			refused = errSNMPInterfacePrefixBudget
			return refused
		}
		used += uint64(len(pdu.Name))
		key, kind, parseErr := parseSNMPInterfaceAddressType(pdu)
		previous, present := types[key]
		if parseErr != nil || !present || previous != 0 {
			refused = errSNMPInterfacePrefixIncomplete
			return refused
		}
		types[key] = kind
		return nil
	})
	if refused != nil {
		return nil, refused
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, errSNMPInterfacePrefixIncomplete
	}
	// Validate the whole matching column before publishing or discarding any
	// address. Missing types must not silently default to unicast.
	for _, kind := range types {
		if kind == 0 {
			return nil, errSNMPInterfacePrefixIncomplete
		}
	}
	out := rows[:0]
	for _, row := range rows {
		if types[snmpInterfaceAddressKey(row)] != 3 {
			out = append(out, row)
		}
	}
	return out, nil
}
