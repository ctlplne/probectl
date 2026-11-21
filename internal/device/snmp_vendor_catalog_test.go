// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestVendorProfileCatalogUsesIndependentMIBFixtures(t *testing.T) {
	if err := validateSNMPVendorProfiles(builtinSNMPVendorProfiles); err != nil {
		t.Fatal(err)
	}
	ciscoCPU := func(index, load uint32) *fakeConn {
		return &fakeConn{tables: map[string]map[uint32]gosnmp.SnmpPDU{
			".1.3.6.1.4.1.9.9.109.1.1.1.1.10": {index: {Type: gosnmp.Gauge32, Value: load}},
		}}
	}
	fixtures := []struct {
		profile, objectID string
		conn              *fakeConn
		want              map[string]float64
		absent            []string
		interfaces        map[uint32]string
	}{
		{
			profile: "cisco-ios", objectID: ".1.3.6.1.4.1.9.1.1695", conn: ciscoCPU(13, 46),
			want: map[string]float64{"probectl.device.cpu.utilization/13": 46},
		},
		{
			profile: "cisco-ios-xe", objectID: ".1.3.6.1.4.1.9.1.2068", conn: ciscoCPU(9, 15),
			want: map[string]float64{"probectl.device.cpu.utilization/9": 15},
		},
		{
			profile: "cisco-nx-os", objectID: ".1.3.6.1.4.1.9.1.1925", conn: ciscoCPU(49, 27),
			want: map[string]float64{"probectl.device.cpu.utilization/49": 27},
		},
		{
			profile: "arista-eos", objectID: ".1.3.6.1.4.1.30065.1.3011.7050.2733.4.972.48.1605.8",
			conn: &fakeConn{tables: map[string]map[uint32]gosnmp.SnmpPDU{
				".1.3.6.1.2.1.25.3.3.1.2": {1: {Type: gosnmp.Integer, Value: 18}, 2: {Type: gosnmp.Integer, Value: 34}},
			}},
			want: map[string]float64{"probectl.device.cpu.utilization/1": 18, "probectl.device.cpu.utilization/2": 34},
		},
		{
			profile: "fortinet-forti-os", objectID: ".1.3.6.1.4.1.12356.101.1.12000",
			conn: &fakeConn{scalars: map[string]gosnmp.SnmpPDU{
				".1.3.6.1.4.1.12356.101.4.1.3.0": {Type: gosnmp.Gauge32, Value: uint32(19)},
				".1.3.6.1.4.1.12356.101.4.1.4.0": {Type: gosnmp.Gauge32, Value: uint32(57)},
			}},
			want: map[string]float64{"probectl.device.cpu.utilization/": 19, "probectl.device.memory.utilization/": 57},
		},
		{
			profile: "juniper-junos", objectID: ".1.3.6.1.4.1.2636.1.1.1.2.63",
			conn: &fakeConn{
				scalars: map[string]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0": {Type: gosnmp.Gauge32, Value: uint32(18)},
					".1.3.6.1.4.1.2636.3.1.13.1.8.9.2.0.0": {Type: gosnmp.Gauge32, Value: uint32(0)},
				},
				tables: map[string]map[uint32]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.2636.3.60.1.1.1.1.5": {11: {Type: gosnmp.Integer, Value: -336}},
					".1.3.6.1.4.1.2636.3.60.1.1.1.1.7": {11: {Type: gosnmp.Integer, Value: -130}},
					".1.3.6.1.2.1.31.1.1.1.1":          {11: {Type: gosnmp.OctetString, Value: []byte("xe-0/0/0")}},
				},
			},
			want: map[string]float64{"probectl.device.cpu.utilization/9.1.0.0": 18,
				"probectl.device.optical.input.power.dbm/@if11": -3.36, "probectl.device.optical.output.power.dbm/@if11": -1.3},
			absent:     []string{"probectl.device.cpu.utilization/9.2.0.0"},
			interfaces: map[uint32]string{11: "xe-0/0/0"},
		},
		{
			profile: "palo-alto-pan-os", objectID: ".1.3.6.1.4.1.25461.2.3.54",
			conn: &fakeConn{
				scalars: map[string]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.25461.2.1.2.3.3.0": {Type: gosnmp.Integer, Value: 621},
				},
				tables: map[string]map[uint32]gosnmp.SnmpPDU{
					".1.3.6.1.2.1.25.3.3.1.2": {4: {Type: gosnmp.Integer, Value: 15}},
				},
			},
			want: map[string]float64{"probectl.device.sessions.active/": 621, "probectl.device.cpu.utilization/4": 15},
		},
		{
			profile: "palo-alto-pa-5450", objectID: ".1.3.6.1.4.1.25461.2.3.57",
			conn: &fakeConn{
				scalars: map[string]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.25461.2.1.2.3.3.0": {Type: gosnmp.Integer, Value: 1612},
				},
				tables: map[string]map[uint32]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.25461.1.1.7.1.4.1.1.1": {842: {Type: gosnmp.Integer, Value: 3000}},
				},
			},
			want: map[string]float64{"probectl.device.sessions.active/": 1612, "probectl.device.power.supply.capacity.watts/842": 3000},
		},
		{
			profile: "mikrotik-router-os", objectID: ".1.3.6.1.4.1.14988.1",
			conn: &fakeConn{
				scalars: map[string]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.14988.1.1.3.10.0": {Type: gosnmp.Integer, Value: 405},
					".1.3.6.1.4.1.14988.1.1.3.17.0": {Type: gosnmp.Gauge32, Value: uint32(2900)},
				},
				tables: map[string]map[uint32]gosnmp.SnmpPDU{
					".1.3.6.1.4.1.14988.1.1.19.1.1.9":  {1: {Type: gosnmp.Integer, Value: -1250}},
					".1.3.6.1.4.1.14988.1.1.19.1.1.10": {1: {Type: gosnmp.Integer, Value: -5250}},
				},
			},
			want: map[string]float64{
				"probectl.device.sensor.temperature.celsius/": 40.5, "probectl.device.fan.speed.rpm/": 2900,
				"probectl.device.optical.input.power.dbm/1": -5.25, "probectl.device.optical.output.power.dbm/1": -1.25,
			},
		},
		{
			profile: "ubiquiti-unifi", objectID: ".1.3.6.1.4.1.41112.1.6",
			conn: &fakeConn{tables: map[string]map[uint32]gosnmp.SnmpPDU{
				".1.3.6.1.4.1.41112.1.6.1.2.1.8": {2: {Type: gosnmp.Integer, Value: 13}},
			}},
			want: map[string]float64{"probectl.device.wifi.stations.associated/2": 13},
		},
		{
			profile: "hpe-aruba-5406r", objectID: ".1.3.6.1.4.1.11.2.3.7.11.160",
			conn: &fakeConn{tables: map[string]map[uint32]gosnmp.SnmpPDU{
				".1.3.6.1.4.1.11.2.14.11.5.1.54.2.1.1.4": {
					3: {Type: gosnmp.Integer, Value: 5}, 4: {Type: gosnmp.Integer, Value: 0}, 5: {Type: gosnmp.Integer, Value: 6},
				},
				".1.3.6.1.4.1.11.2.14.11.5.1.55.1.1.1.2": {
					1: {Type: gosnmp.Integer, Value: 3}, 2: {Type: gosnmp.Integer, Value: 9}, 3: {Type: gosnmp.Integer, Value: 6},
				},
			}},
			want: map[string]float64{"probectl.device.fan.state/3": 5, "probectl.device.fan.state/4": 0,
				"probectl.device.power.supply.state/1": 3, "probectl.device.power.supply.state/2": 9},
			absent: []string{"probectl.device.fan.state/5", "probectl.device.power.supply.state/3"},
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.profile, func(t *testing.T) {
			port := serveSNMPVendorFixture(t, fixture.objectID, fixture.conn)
			target := Target{Address: "127.0.0.1", Port: port, Transport: TransportSNMPv2c, SNMPVendorProfile: "auto"}
			if err := configureSNMPVendorTarget(&target, builtinSNMPVendorProfiles); err != nil {
				t.Fatal(err)
			}
			conn, err := dialSNMP(target, Credential{Community: "owned-loopback-fixture"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			const tenant = "catalog-fixture-owner"
			rows, inventory, err := pollSNMP(t.Context(), conn, target, tenant, "owned-collector", pollTime)
			if err != nil || inventory.VendorProfile != fixture.profile || inventory.SysObjectID != fixture.objectID {
				t.Fatal("published product identity did not select the expected profile through SNMP", inventory, err)
			}
			observed := map[string]bool{}
			for _, row := range rows {
				key := row.Name + "/" + row.Component
				if row.IfIndex != 0 {
					key += "@if" + strconv.FormatUint(uint64(row.IfIndex), 10)
				}
				if slices.Contains(fixture.absent, key) {
					t.Fatal("an unavailable source became a measurement", row)
				}
				value, found := fixture.want[key]
				if !found {
					continue
				}
				if observed[key] || math.Abs(row.Value-value) > 1e-9 || row.TenantID != tenant || row.Device != target.Address {
					t.Fatal("normalized measurement changed identity, value or scope", row)
				}
				if name, bound := fixture.interfaces[row.IfIndex]; bound && row.IfName != name {
					t.Fatal("the optical reading did not preserve its exact IF-MIB label", row)
				}
				source := row.ToProto().GetSnmpMetricSource()
				if source.GetProfileId() != fixture.profile || source.GetSystemObjectId() != fixture.objectID ||
					!ValidSNMPMetricSource(row.Name, row.Unit, source.GetProfileId(), source.GetSystemObjectId(),
						source.GetMibObject(), source.GetOid()) {
					t.Fatal("the original profile and object identity did not survive wire conversion", source)
				}
				observed[key] = true
			}
			if len(observed) != len(fixture.want) {
				t.Fatal("published MIB fixture lost a reading", observed, fixture.want)
			}
		})
	}
}

func serveSNMPVendorFixture(t *testing.T, objectID string, fixture *fakeConn) uint16 {
	t.Helper()
	rows := map[string]gosnmp.SnmpPDU{
		".1.3.6.1.2.1.1.1.0": {Type: gosnmp.OctetString, Value: []byte("owned vendor profile simulation")},
		".1.3.6.1.2.1.1.2.0": {Type: gosnmp.ObjectIdentifier, Value: objectID},
		".1.3.6.1.2.1.1.3.0": {Type: gosnmp.TimeTicks, Value: uint32(5000)},
		".1.3.6.1.2.1.1.5.0": {Type: gosnmp.OctetString, Value: []byte("owned-fixture")},
	}
	for oid, row := range fixture.scalars {
		rows[oid] = row
	}
	for root, table := range fixture.tables {
		for index, row := range table {
			rows[fmt.Sprintf("%s.%d", root, index)] = row
		}
	}
	order := make([]string, 0, len(rows))
	for oid, row := range rows {
		row.Name = oid
		rows[oid] = row
		order = append(order, oid)
	}
	slices.SortFunc(order, compareFixtureOID)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveSNMPFixtureRequests(listener, rows, order)
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func serveSNMPFixtureRequests(listener *net.UDPConn, rows map[string]gosnmp.SnmpPDU, order []string) {
	decoder := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	var buffer [4096]byte
	for {
		length, source, err := listener.ReadFromUDPAddrPort(buffer[:])
		if err != nil {
			return
		}
		request, err := decoder.SnmpDecodePacket(buffer[:length])
		if err != nil || request.Community != "owned-loopback-fixture" || request.Version != gosnmp.Version2c {
			continue
		}
		switch request.PDUType {
		case gosnmp.GetRequest, gosnmp.GetNextRequest, gosnmp.GetBulkRequest:
		default:
			continue
		}
		response := &gosnmp.SnmpPacket{Version: request.Version, Community: request.Community,
			PDUType: gosnmp.GetResponse, RequestID: request.RequestID}
		for _, query := range request.Variables {
			response.Variables = append(response.Variables, snmpFixtureResponseRow(request.PDUType, query.Name, rows, order))
		}
		if encoded, err := response.MarshalMsg(); err == nil {
			_, _ = listener.WriteToUDPAddrPort(encoded, source)
		}
	}
}

func snmpFixtureResponseRow(kind gosnmp.PDUType, oid string, rows map[string]gosnmp.SnmpPDU, order []string) gosnmp.SnmpPDU {
	if kind == gosnmp.GetRequest {
		if result, found := rows[oid]; found {
			return result
		}
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.NoSuchObject}
	}
	for _, candidate := range order {
		if compareFixtureOID(candidate, oid) > 0 {
			return rows[candidate]
		}
	}
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView}
}

func compareFixtureOID(a, b string) int {
	left, right := strings.Split(strings.TrimPrefix(a, "."), "."), strings.Split(strings.TrimPrefix(b, "."), ".")
	return slices.CompareFunc(left, right, func(x, y string) int {
		first, _ := strconv.Atoi(x)
		second, _ := strconv.Atoi(y)
		return first - second
	})
}
