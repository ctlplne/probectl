// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/ctlplne/probectl/internal/entity"
)

// RFC4293 IP-MIB ipAddressIfIndex: index (InetAddressType, InetAddress),
// value IF-MIB InterfaceIndex. Unlike the deprecated ipAddrTable, this is
// IP-version neutral. Read only; no SET operations or new data-source family.
const oidIPAddressIfIndex = ".1.3.6.1.2.1.4.34.1.3"

type snmpInterfaceAddressWalker interface {
	walkInterfaceAddresses(context.Context, gosnmp.WalkFunc) error
	walkInterfaceAddressTypes(context.Context, gosnmp.WalkFunc) error
}

type snmpInterfaceAddress struct {
	index   uint32
	address netip.Addr
	zone    uint32
	scoped  bool
}

func parseSNMPInterfaceAddress(pdu gosnmp.SnmpPDU) (snmpInterfaceAddress, error) {
	none := snmpInterfaceAddress{}
	if pdu.Type != gosnmp.Integer || len(pdu.Name) > 256 {
		return none, errSNMPInterfacePrefixIncomplete
	}
	suffix, ok := strings.CutPrefix(strings.TrimPrefix(pdu.Name, "."), strings.TrimPrefix(oidIPAddressIfIndex, ".")+".")
	if !ok {
		return none, errSNMPInterfacePrefixIncomplete
	}
	fields := strings.Split(suffix, ".")
	if len(fields) < 3 {
		return none, errSNMPInterfacePrefixIncomplete
	}
	var size int
	var scoped bool
	switch fields[0] {
	case "1":
		size = 4
	case "2":
		size = 16
	case "3":
		size, scoped = 4, true
	case "4":
		size, scoped = 16, true
	default:
		return none, errSNMPInterfacePrefixIncomplete
	}
	octets := size
	if scoped {
		octets += 4
	}
	if fields[1] != strconv.Itoa(octets) || len(fields) != octets+2 {
		return none, errSNMPInterfacePrefixIncomplete
	}
	var raw [20]byte
	for i, field := range fields[2:] {
		value, err := snmpPrefixOIDNumber(field, 8)
		if err != nil {
			return none, errSNMPInterfacePrefixIncomplete
		}
		raw[i] = byte(value)
	}
	index, err := snmpAddressInterfaceIndex(pdu.Value)
	if err != nil {
		return none, err
	}
	address := netip.AddrFrom16([16]byte(raw[:16]))
	if size == 4 {
		address = netip.AddrFrom4([4]byte(raw[:4]))
	}
	zone := uint32(0)
	if scoped {
		zone = binary.BigEndian.Uint32(raw[size : size+4])
	}
	return snmpInterfaceAddress{index: index, address: address, zone: zone, scoped: scoped}, nil
}

func snmpAddressIndex[T snmpPrefixInteger](value T) (uint32, error) {
	if value < 1 || uint64(value) > 2147483647 {
		return 0, errSNMPInterfacePrefixIncomplete
	}
	return uint32(value), nil
}

func snmpAddressInterfaceIndex(value any) (uint32, error) {
	switch value := value.(type) {
	case int:
		return snmpAddressIndex(value)
	case int8:
		return snmpAddressIndex(value)
	case int16:
		return snmpAddressIndex(value)
	case int32:
		return snmpAddressIndex(value)
	case int64:
		return snmpAddressIndex(value)
	case uint:
		return snmpAddressIndex(value)
	case uint8:
		return snmpAddressIndex(value)
	case uint16:
		return snmpAddressIndex(value)
	case uint32:
		return snmpAddressIndex(value)
	case uint64:
		return snmpAddressIndex(value)
	default:
		return 0, errSNMPInterfacePrefixIncomplete
	}
}

func collectSNMPInterfaceAddresses(ctx context.Context, conn snmpInterfaceAddressWalker, limits snmpInterfacePrefixLimits) ([]snmpInterfaceAddress, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if conn == nil || limits.Rows == 0 || limits.IndexBytes == 0 {
		return nil, errSNMPInterfacePrefixBudget
	}
	rows := make([]snmpInterfaceAddress, 0)
	seen := map[snmpInterfaceAddress]bool{}
	var used uint64
	var refused error
	err := conn.walkInterfaceAddresses(ctx, func(pdu gosnmp.SnmpPDU) error {
		if refused != nil {
			return refused
		}
		if refused = ctx.Err(); refused != nil {
			return refused
		}
		if uint64(len(rows)) >= limits.Rows || uint64(len(pdu.Name)) > limits.IndexBytes-used {
			refused = errSNMPInterfacePrefixBudget
			return refused
		}
		used += uint64(len(pdu.Name))
		row, parseErr := parseSNMPInterfaceAddress(pdu)
		key := row
		key.index = 0 // IP-MIB indexes the address, not its reported interface.
		if parseErr != nil || seen[key] {
			refused = errSNMPInterfacePrefixIncomplete
			return refused
		}
		seen[key] = true
		rows = append(rows, row)
		return nil
	})
	if refused != nil {
		return nil, refused
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		if len(rows) == 0 && errors.Is(err, errors.ErrUnsupported) {
			return nil, errors.ErrUnsupported
		}
		return nil, errSNMPInterfacePrefixIncomplete
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].index != rows[j].index {
			return rows[i].index < rows[j].index
		}
		if compared := rows[i].address.Compare(rows[j].address); compared != 0 {
			return compared < 0
		}
		if rows[i].scoped != rows[j].scoped {
			return !rows[i].scoped
		}
		return rows[i].zone < rows[j].zone
	})
	limits.IndexBytes -= used
	return selectSNMPInterfaceAddressTypes(ctx, conn, rows, limits)
}

func collectSNMPModernAddresses(ctx context.Context, conn snmpConn, inv *Inventory) {
	walker, supported := conn.(snmpInterfaceAddressWalker)
	if !supported {
		return
	}
	rows, err := collectSNMPInterfaceAddresses(ctx, walker, snmpInterfacePrefixLimits{
		Rows: entity.MaxSNMPInterfacePrefixWireBytes / 8, IndexBytes: entity.MaxSNMPInterfacePrefixWireBytes * 32,
	})
	if errors.Is(err, errors.ErrUnsupported) {
		return // The agent explicitly lacks this MIB: retain legacy IPv4 input.
	}
	// A complete modern table replaces legacy addresses. On failure, publish
	// no partial addresses or role prefix epoch; retain independent raw counters.
	for index, iface := range inv.Interfaces {
		iface.Addrs, iface.ScopedAddrs = nil, nil
		inv.Interfaces[index] = iface
	}
	if err != nil {
		inv.addressesUnavailable = true
		return
	}
	for _, row := range rows {
		iface := inv.Interfaces[row.index]
		iface.Index = row.index
		if row.scoped {
			// Zones have meaning only on this observed device/interface. Keep
			// them in raw metrics; never forge an unscoped canonical alias.
			iface.ScopedAddrs = append(iface.ScopedAddrs, row.address.String()+"%"+strconv.FormatUint(uint64(row.zone), 10))
		} else {
			iface.Addrs = append(iface.Addrs, row.address)
		}
		inv.Interfaces[row.index] = iface
	}
}
