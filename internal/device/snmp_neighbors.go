// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gosnmp/gosnmp"
)

// LLDP-MIB remote systems data. The standard table index is
// (timeMark, localPortNum, remIndex); no vendor parser is involved.
const (
	oidLLDPLocPortID       = ".1.0.8802.1.1.2.1.3.7.1.3"
	oidLLDPLocPortDesc     = ".1.0.8802.1.1.2.1.3.7.1.4"
	oidLLDPRemTTL          = ".1.0.8802.1.1.2.1.4.1.1.3"
	oidLLDPRemChassisID    = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLLDPRemPortID       = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLLDPRemPortDesc     = ".1.0.8802.1.1.2.1.4.1.1.8"
	oidLLDPRemSysName      = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLLDPRemSysDesc      = ".1.0.8802.1.1.2.1.4.1.1.10"
	oidLLDPRemSysCapEnable = ".1.0.8802.1.1.2.1.4.1.1.12"

	// CISCO-CDP-MIB cache table, indexed by (local ifIndex, remote index).
	// CDP is vendor-specific on the wire but read here through the existing
	// SNMP transport with no SDK, executable, or runtime dependency.
	oidCDPCacheAddress      = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	oidCDPCacheVersion      = ".1.3.6.1.4.1.9.9.23.1.2.1.1.5"
	oidCDPCacheDeviceID     = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	oidCDPCacheDevicePort   = ".1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	oidCDPCachePlatform     = ".1.3.6.1.4.1.9.9.23.1.2.1.1.8"
	oidCDPCacheCapabilities = ".1.3.6.1.4.1.9.9.23.1.2.1.1.9"
)

type lldpRow struct {
	localPort, chassis, port, portDesc, name, sysDesc string
	ttl                                               time.Duration
	capabilities                                      []string
}

type cdpRow struct {
	ifIndex                    uint32
	address, version, deviceID string
	port, platform             string
	capabilities               []string
}

// pollSNMPNeighbors performs bounded read-only LLDP/CDP table walks over the
// same authenticated session as the ordinary device poll. Missing MIBs degrade
// to an empty protocol subset; no scan or follow-up connection occurs.
func pollSNMPNeighbors(conn snmpConn, dev Target, tenant, agent string, inv Inventory, now time.Time) ([]NeighborEvidence, error) {
	if !dev.Neighbors {
		return nil, nil
	}
	fallbackFresh := 2 * dev.Interval
	if fallbackFresh < 2*time.Minute {
		fallbackFresh = 2 * time.Minute
	}
	if fallbackFresh > 10*time.Minute {
		fallbackFresh = 10 * time.Minute
	}
	lldp, err := pollLLDPNeighbors(conn, dev, tenant, agent, inv, now, fallbackFresh)
	if err != nil {
		return nil, err
	}
	cdp, err := pollCDPNeighbors(conn, dev, tenant, agent, inv, now, fallbackFresh)
	if err != nil {
		return nil, err
	}
	out := make([]NeighborEvidence, 0, len(lldp)+len(cdp))
	out = append(out, lldp...)
	out = append(out, cdp...)
	if len(out) > MaxNeighborsPerDevice {
		out = out[:MaxNeighborsPerDevice]
	}
	valid, err := ValidateNeighborSnapshot(NeighborSnapshot{
		TenantID: tenant, AgentID: agent, DeviceAddress: dev.Address,
		DeviceName: inv.SysName, ObservedAt: now, Neighbors: out,
	})
	if err != nil {
		return nil, fmt.Errorf("validate neighbor snapshot: %w", err)
	}
	return valid.Neighbors, nil
}

func pollLLDPNeighbors(conn snmpConn, dev Target, tenant, agent string, inv Inventory, now time.Time, fallback time.Duration) ([]NeighborEvidence, error) {
	walk := func(field, root string, indexParts int, fn func([]uint32, gosnmp.SnmpPDU)) error {
		if err := walkIndexed(conn, root, indexParts, fn); err != nil {
			return fmt.Errorf("lldp %s: %w", field, err)
		}
		return nil
	}
	localPorts := map[uint32]string{}
	if err := walk("local port ID", oidLLDPLocPortID, 1, func(index []uint32, p gosnmp.SnmpPDU) {
		localPorts[index[0]] = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("local port description", oidLLDPLocPortDesc, 1, func(index []uint32, p gosnmp.SnmpPDU) {
		if localPorts[index[0]] == "" {
			localPorts[index[0]] = neighborPDUText(p)
		}
	}); err != nil {
		return nil, err
	}
	rows := map[[3]uint32]*lldpRow{}
	row := func(index []uint32) *lldpRow {
		key := [3]uint32{index[0], index[1], index[2]}
		if rows[key] == nil {
			rows[key] = &lldpRow{localPort: localPorts[index[1]]}
		}
		return rows[key]
	}
	if err := walk("remote TTL", oidLLDPRemTTL, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).ttl = time.Duration(pduFloat(p)) * time.Second
	}); err != nil {
		return nil, err
	}
	if err := walk("remote chassis ID", oidLLDPRemChassisID, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).chassis = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("remote port ID", oidLLDPRemPortID, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).port = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("remote port description", oidLLDPRemPortDesc, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).portDesc = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("remote system name", oidLLDPRemSysName, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).name = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("remote system description", oidLLDPRemSysDesc, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).sysDesc = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("remote capabilities", oidLLDPRemSysCapEnable, 3, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).capabilities = decodeLLDPCapabilities(p)
	}); err != nil {
		return nil, err
	}
	keys := make([][3]uint32, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][1] != keys[j][1] {
			return keys[i][1] < keys[j][1]
		}
		return keys[i][2] < keys[j][2]
	})
	out := make([]NeighborEvidence, 0, min(len(keys), MaxNeighborsPerDevice))
	for _, key := range keys {
		r := rows[key]
		localPort := r.localPort
		if localPort == "" {
			localPort = "lldp-port-" + strconv.FormatUint(uint64(key[1]), 10)
		}
		remotePort := r.port
		if remotePort == "" {
			remotePort = r.portDesc
		}
		ttl := r.ttl
		if ttl < 30*time.Second || ttl > time.Hour {
			ttl = fallback
		}
		confidence := 0.95
		if r.chassis == "" || remotePort == "" {
			confidence = 0.75
		}
		out = append(out, NeighborEvidence{
			TenantID: tenant, AgentID: agent,
			LocalDeviceAddress: dev.Address, LocalDeviceName: inv.SysName,
			LocalIfIndex: matchInterfaceIndex(inv, localPort), LocalPortID: localPort,
			RemoteChassisID: r.chassis, RemoteDeviceName: r.name, RemotePortID: remotePort,
			RemotePlatform: r.sysDesc, Capabilities: r.capabilities,
			Protocol: NeighborProtocolLLDP, Confidence: confidence,
			ObservedAt: now, FreshUntil: now.Add(ttl),
		})
		if len(out) == MaxNeighborsPerDevice {
			break
		}
	}
	return out, nil
}

func pollCDPNeighbors(conn snmpConn, dev Target, tenant, agent string, inv Inventory, now time.Time, freshness time.Duration) ([]NeighborEvidence, error) {
	walk := func(field, root string, fn func([]uint32, gosnmp.SnmpPDU)) error {
		if err := walkIndexed(conn, root, 2, fn); err != nil {
			return fmt.Errorf("cdp %s: %w", field, err)
		}
		return nil
	}
	rows := map[[2]uint32]*cdpRow{}
	row := func(index []uint32) *cdpRow {
		key := [2]uint32{index[0], index[1]}
		if rows[key] == nil {
			rows[key] = &cdpRow{ifIndex: index[0]}
		}
		return rows[key]
	}
	if err := walk("management address", oidCDPCacheAddress, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).address = pduAddress(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("version", oidCDPCacheVersion, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).version = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("device ID", oidCDPCacheDeviceID, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).deviceID = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("device port", oidCDPCacheDevicePort, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).port = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("platform", oidCDPCachePlatform, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).platform = neighborPDUText(p)
	}); err != nil {
		return nil, err
	}
	if err := walk("capabilities", oidCDPCacheCapabilities, func(index []uint32, p gosnmp.SnmpPDU) {
		row(index).capabilities = decodeCDPCapabilities(p)
	}); err != nil {
		return nil, err
	}
	keys := make([][2]uint32, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	out := make([]NeighborEvidence, 0, min(len(keys), MaxNeighborsPerDevice))
	for _, key := range keys {
		r := rows[key]
		localPort := "ifIndex " + strconv.FormatUint(uint64(r.ifIndex), 10)
		if ifc, ok := inv.Interfaces[r.ifIndex]; ok && ifc.Name != "" {
			localPort = ifc.Name
		}
		confidence := 0.9
		if r.deviceID == "" || r.port == "" {
			confidence = 0.7
		}
		out = append(out, NeighborEvidence{
			TenantID: tenant, AgentID: agent,
			LocalDeviceAddress: dev.Address, LocalDeviceName: inv.SysName,
			LocalIfIndex: r.ifIndex, LocalPortID: localPort,
			RemoteChassisID: r.deviceID, RemoteDeviceName: r.deviceID, RemotePortID: r.port,
			RemoteManagementAddress: r.address, RemotePlatform: firstNonBlank(r.platform, r.version),
			Capabilities: r.capabilities, Protocol: NeighborProtocolCDP, Confidence: confidence,
			ObservedAt: now, FreshUntil: now.Add(freshness),
		})
		if len(out) == MaxNeighborsPerDevice {
			break
		}
	}
	return out, nil
}

func walkIndexed(conn snmpConn, root string, indexParts int, fn func([]uint32, gosnmp.SnmpPDU)) error {
	err := conn.BulkWalk(root, func(p gosnmp.SnmpPDU) error {
		switch p.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
			return nil
		}
		index, ok := trailingIndex(p.Name, root, indexParts)
		if ok {
			fn(index, p)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("bulk walk %s: %w", root, err)
	}
	return nil
}

func trailingIndex(name, root string, parts int) ([]uint32, bool) {
	tail := strings.TrimPrefix(name, root+".")
	if tail == name || tail == "" {
		return nil, false
	}
	fields := strings.Split(tail, ".")
	if len(fields) != parts {
		return nil, false
	}
	out := make([]uint32, parts)
	for i, field := range fields {
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, false
		}
		out[i] = uint32(value)
	}
	return out, true
}

func matchInterfaceIndex(inv Inventory, port string) uint32 {
	for idx, ifc := range inv.Interfaces {
		if port == ifc.Name || port == ifc.Descr {
			return idx
		}
	}
	return 0
}

func neighborPDUText(p gosnmp.SnmpPDU) string {
	switch value := p.Value.(type) {
	case []byte:
		if len(value) == 0 {
			return ""
		}
		printable := true
		for _, b := range value {
			if b < 0x20 || b > unicode.MaxASCII {
				printable = false
				break
			}
		}
		if printable {
			return string(value)
		}
		if len(value) == 6 {
			parts := make([]string, len(value))
			for i, b := range value {
				parts[i] = fmt.Sprintf("%02x", b)
			}
			return strings.Join(parts, ":")
		}
		return hex.EncodeToString(value)
	case string:
		return value
	default:
		return pduString(p)
	}
}

func pduAddress(p gosnmp.SnmpPDU) string {
	value, ok := p.Value.([]byte)
	if !ok {
		return neighborPDUText(p)
	}
	if len(value) == 4 || len(value) == 16 {
		if addr, ok := netip.AddrFromSlice(value); ok {
			return addr.String()
		}
	}
	return neighborPDUText(p)
}

func decodeLLDPCapabilities(p gosnmp.SnmpPDU) []string {
	value, ok := p.Value.([]byte)
	if !ok || len(value) == 0 {
		return nil
	}
	names := []string{"other", "repeater", "bridge", "wlan", "router", "telephone", "docsis", "station"}
	var out []string
	for bit, name := range names {
		if value[0]&(1<<uint(7-bit)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func decodeCDPCapabilities(p gosnmp.SnmpPDU) []string {
	var mask uint64
	if value, ok := p.Value.([]byte); ok {
		for _, b := range value {
			mask = mask<<8 | uint64(b)
		}
	} else {
		mask = uint64(pduFloat(p))
	}
	names := []struct {
		bit  uint64
		name string
	}{
		{0x01, "router"}, {0x02, "transparent-bridge"}, {0x04, "source-route-bridge"},
		{0x08, "switch"}, {0x10, "host"}, {0x20, "igmp"}, {0x40, "repeater"},
	}
	var out []string
	for _, item := range names {
		if mask&item.bit != 0 {
			out = append(out, item.name)
		}
	}
	return out
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
