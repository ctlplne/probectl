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
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/ctlplne/probectl/internal/entity"
)

type modernAddressConn struct {
	*ipWalkConn
	rows    []gosnmp.SnmpPDU
	err     error
	types   []gosnmp.SnmpPDU
	typeErr error
}

func (c *modernAddressConn) walkInterfaceAddresses(ctx context.Context, fn gosnmp.WalkFunc) error {
	for _, row := range c.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(row); err != nil {
			return err
		}
	}
	return c.err
}

// Modeled complete RFC4293 companion column. Tests can replace it with a
// complete broadcast/anycast population or a deliberately incomplete epoch.
func (c *modernAddressConn) walkInterfaceAddressTypes(ctx context.Context, fn gosnmp.WalkFunc) error {
	rows := c.types
	if rows == nil {
		for _, row := range c.rows {
			row.Name = strings.Replace(row.Name, oidIPAddressIfIndex, ".1.3.6.1.2.1.4.34.1.4", 1)
			row.Value = int64(1)
			rows = append(rows, row)
		}
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(row); err != nil {
			return err
		}
	}
	return c.typeErr
}

func addressRow(address string, index uint32, zone *uint32) gosnmp.SnmpPDU {
	ip := netip.MustParseAddr(address)
	value, kind := ip.AsSlice(), 2
	if ip.Is4() {
		kind = 1
	}
	if zone != nil {
		kind += 2
		value = binary.BigEndian.AppendUint32(value, *zone)
	}
	parts := []string{strconv.Itoa(kind), strconv.Itoa(len(value))}
	for _, octet := range value {
		parts = append(parts, strconv.Itoa(int(octet)))
	}
	return gosnmp.SnmpPDU{Name: oidIPAddressIfIndex + "." + strings.Join(parts, "."), Type: gosnmp.Integer, Value: int64(index)}
}

func modernAddressFixture() *modernAddressConn {
	zone4, zone6 := uint32(7), uint32(math.MaxUint32)
	return &modernAddressConn{ipWalkConn: &ipWalkConn{fakeConn: healthyConn(), ipRows: map[string]uint32{"192.0.2.1": 1}}, rows: []gosnmp.SnmpPDU{
		addressRow("192.0.2.1", 1, nil), addressRow("fd42:e8:1::11", 1, nil), addressRow("2001:db8::2", 2, nil),
		addressRow("198.51.100.2", 2, &zone4), addressRow("fe80::1", 2, &zone6),
	}}
}

func TestSNMPPollInterfaceAddressesKeepDualStackWholeEpochAndTenantEvidence(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		conn := modernAddressFixture()
		metrics, inv, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.1", Transport: TransportSNMPv2c}, tenant, "agent-1", pollTime)
		if err != nil || inv.addressesUnavailable || len(inv.Interfaces[1].Addrs) != 2 || len(inv.Interfaces[2].Addrs) != 1 || len(inv.Interfaces[2].ScopedAddrs) != 2 {
			t.Fatal("complete dual-stack IP-MIB addresses were lost", inv.Interfaces, err)
		}
		foundIPv6, foundZone := false, false
		for _, metric := range metrics {
			if metric.TenantID != tenant {
				t.Fatal("dual-stack interface metric crossed its collector tenant")
			}
			foundIPv6 = foundIPv6 || slices.Contains(metric.InterfaceAddresses, "fd42:e8:1::11")
			foundZone = foundZone || slices.Contains(metric.InterfaceAddresses, "fe80::1%4294967295")
		}
		if !foundIPv6 || !foundZone || !slices.Contains(inv.Interfaces[2].ScopedAddrs, "198.51.100.2%7") {
			t.Fatal("raw interface metrics lost IPv6 or complete scoped address values")
		}
		runtime, evidence, _ := prefixPollRuntime(t, "22222222-2222-4222-8222-222222222222", conn)
		runtime.cfg.TenantID = tenant
		runtime.emitSNMPEntityEvidence(t.Context(), runtime.cfg.Devices[0], inv, nil, pollTime)
		alias := false
		for _, claim := range evidence.claims {
			if claim.Source.AgentID != runtime.cfg.AgentID || strings.Contains(claim.Alias.Value, "%") {
				t.Fatal("scoped address invented an unscoped identity or crossed tenant evidence", claim.Alias.Kind)
			}
			alias = alias || claim.Alias.Kind == entity.AddressAlias && claim.Alias.Value == "fd42:e8:1::11" && claim.SourceRef == "snmp:ifIndex:1"
		}
		if !alias {
			t.Fatal("real poll path omitted IPv6 interface evidence")
		}
	}
}

func TestSNMPInterfaceAddressesRefusePartialMalformedOrUnadmittedTables(t *testing.T) {
	for _, mutate := range []func(*modernAddressConn){
		func(c *modernAddressConn) { c.err = errors.New("modeled late transport failure") },
		func(c *modernAddressConn) { c.rows[3].Name += ".1" },
		func(c *modernAddressConn) { c.rows[3].Type = gosnmp.OctetString },
		func(c *modernAddressConn) { c.rows[3].Value = uint64(math.MaxUint64) },
		func(c *modernAddressConn) { c.rows[3].Value = int64(-1) },
		func(c *modernAddressConn) { c.rows[3].Value = float64(7) },
		func(c *modernAddressConn) { c.rows = append(c.rows, c.rows[0]) },
	} {
		conn := modernAddressFixture()
		mutate(conn)
		metrics, inv, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.1"}, "tenant", "agent", pollTime)
		if err != nil || !inv.addressesUnavailable || len(metrics) == 0 {
			t.Fatal("partial address failure removed independent raw counters or retained authority", err)
		}
		for _, iface := range inv.Interfaces {
			if len(iface.Addrs) != 0 || len(iface.ScopedAddrs) != 0 {
				t.Fatal("partial modern address table escaped as current inventory")
			}
		}
		runtime, _, _ := prefixPollRuntime(t, "22222222-2222-4222-8222-222222222222", conn)
		runtime.collectSNMPPrefixEvidence(t.Context(), conn, &inv)
		if !inv.prefixAttempted || inv.interfacePrefixes != nil || runtime.stats.InterfacePrefixUnavailable.Load() != 1 {
			t.Fatal("incomplete address table published a complete role prefix epoch")
		}
	}
	conn := modernAddressFixture()
	if rows, err := collectSNMPInterfaceAddresses(t.Context(), conn, snmpInterfacePrefixLimits{Rows: 2, IndexBytes: 4096}); !errors.Is(err, errSNMPInterfacePrefixBudget) || rows != nil {
		t.Fatal("address admission returned a truncated table", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rows, err := collectSNMPInterfaceAddresses(ctx, conn, snmpInterfacePrefixLimits{Rows: 10, IndexBytes: 4096}); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("canceled address collection returned partial rows", err)
	}
	conn = modernAddressFixture()
	conn.rows, conn.err = nil, errors.ErrUnsupported
	_, inv, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.1"}, "tenant", "agent", pollTime)
	if err != nil || inv.addressesUnavailable || !slices.Contains(inv.Interfaces[1].Addrs, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("unsupported modern IP-MIB lost existing legacy IPv4 evidence", err)
	}
}

func TestSNMPModernAddressTypeNeverTurnsBroadcastIntoOwnedHop(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		conn := modernAddressFixture()
		conn.rows = append(conn.rows, addressRow("172.17.255.255", 2, nil), addressRow("2001:db8::a", 2, nil))
		for _, row := range conn.rows {
			row.Name = strings.Replace(row.Name, oidIPAddressIfIndex, ".1.3.6.1.2.1.4.34.1.4", 1)
			row.Value = int64(1)
			if strings.HasSuffix(row.Name, ".172.17.255.255") {
				row.Value = int64(3)
			}
			conn.types = append(conn.types, row)
		}
		conn.types[len(conn.types)-1].Value = int64(2)
		metrics, inv, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.1"}, tenant, "agent", pollTime)
		if err != nil || inv.addressesUnavailable || len(metrics) == 0 {
			t.Fatal("complete IP-MIB type epoch lost raw counters", err)
		}
		if slices.Contains(inv.Interfaces[2].Addrs, netip.MustParseAddr("172.17.255.255")) {
			t.Fatal("IP-MIB broadcast entry became an owned interface address or topology hop")
		}
		if !slices.Contains(inv.Interfaces[2].Addrs, netip.MustParseAddr("2001:db8::a")) || !slices.Contains(inv.Interfaces[1].Addrs, netip.MustParseAddr("fd42:e8:1::11")) {
			t.Fatal("address type selection removed supported anycast or dual-stack input")
		}
		for _, m := range metrics {
			if m.TenantID != tenant {
				t.Fatal("typed IP-MIB epoch crossed its tenant")
			}
		}
	}
}

func TestSNMPModernAddressTypeRequiresCompleteMatchingColumn(t *testing.T) {
	for _, change := range []func(*modernAddressConn){
		func(c *modernAddressConn) { c.types = []gosnmp.SnmpPDU{} },
		func(c *modernAddressConn) { c.typeErr = errors.New("late type table failure") },
		func(c *modernAddressConn) {
			row := c.rows[0]
			row.Name = strings.Replace(row.Name, oidIPAddressIfIndex, ".1.3.6.1.2.1.4.34.1.4", 1)
			row.Value = int64(4)
			c.types = []gosnmp.SnmpPDU{row}
		},
	} {
		conn := modernAddressFixture()
		change(conn)
		_, inv, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.1"}, "tenant", "agent", pollTime)
		if err != nil || !inv.addressesUnavailable {
			t.Fatal("incomplete address type table retained current interface authority", err)
		}
		for _, iface := range inv.Interfaces {
			if len(iface.Addrs) > 0 || len(iface.ScopedAddrs) > 0 {
				t.Fatal("partial typed address table escaped")
			}
		}
	}
}
