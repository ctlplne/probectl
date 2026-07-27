// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type neighborConn struct {
	columns map[string][]gosnmp.SnmpPDU
}

func (c neighborConn) Get([]string) ([]gosnmp.SnmpPDU, error) { return nil, nil }
func (c neighborConn) Close() error                           { return nil }
func (c neighborConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	for _, pdu := range c.columns[root] {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

func TestPollSNMPNeighborsNormalizesLLDPAndCDPWithoutScanning(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	p := func(root, index string, value any) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: root + "." + index, Value: value}
	}
	conn := neighborConn{columns: map[string][]gosnmp.SnmpPDU{
		oidLLDPLocPortID:        {p(oidLLDPLocPortID, "5", []byte("xe-0/0/5"))},
		oidLLDPRemTTL:           {p(oidLLDPRemTTL, "10.5.1", 120)},
		oidLLDPRemChassisID:     {p(oidLLDPRemChassisID, "10.5.1", []byte{0, 17, 34, 51, 68, 85})},
		oidLLDPRemPortID:        {p(oidLLDPRemPortID, "10.5.1", []byte("Ethernet1/1"))},
		oidLLDPRemSysName:       {p(oidLLDPRemSysName, "10.5.1", []byte("leaf-1"))},
		oidLLDPRemSysDesc:       {p(oidLLDPRemSysDesc, "10.5.1", []byte("switch-os"))},
		oidLLDPRemSysCapEnable:  {p(oidLLDPRemSysCapEnable, "10.5.1", []byte{0x28})}, // bridge + router
		oidCDPCacheAddress:      {p(oidCDPCacheAddress, "7.1", []byte{192, 0, 2, 7})},
		oidCDPCacheDeviceID:     {p(oidCDPCacheDeviceID, "7.1", []byte("dist-7"))},
		oidCDPCacheDevicePort:   {p(oidCDPCacheDevicePort, "7.1", []byte("Gi1/0/48"))},
		oidCDPCachePlatform:     {p(oidCDPCachePlatform, "7.1", []byte("C9300"))},
		oidCDPCacheCapabilities: {p(oidCDPCacheCapabilities, "7.1", 0x09)}, // router + switch
	}}
	inv := Inventory{
		Device: "192.0.2.1", SysName: "core-1",
		Interfaces: map[uint32]Interface{
			5: {Index: 5, Name: "xe-0/0/5"},
			7: {Index: 7, Name: "Gi0/7"},
		},
	}
	got := pollSNMPNeighbors(conn, Target{
		Address: "192.0.2.1", Transport: TransportSNMPv3,
		Interval: time.Minute, Neighbors: true,
	}, "tenant-a", "agent-a", inv, now)
	if len(got) != 2 {
		t.Fatalf("neighbors = %+v, want LLDP + CDP", got)
	}
	var lldp, cdp NeighborEvidence
	for _, neighbor := range got {
		switch neighbor.Protocol {
		case NeighborProtocolLLDP:
			lldp = neighbor
		case NeighborProtocolCDP:
			cdp = neighbor
		}
	}
	if lldp.Protocol != NeighborProtocolLLDP || lldp.LocalIfIndex != 5 ||
		lldp.LocalPortID != "xe-0/0/5" || lldp.RemoteDeviceName != "leaf-1" ||
		lldp.RemotePortID != "Ethernet1/1" || lldp.RemoteChassisID != "00:11:22:33:44:55" ||
		!lldp.FreshUntil.Equal(now.Add(120*time.Second)) {
		t.Fatalf("LLDP evidence = %+v", lldp)
	}
	if cdp.Protocol != NeighborProtocolCDP || cdp.LocalIfIndex != 7 ||
		cdp.LocalPortID != "Gi0/7" || cdp.RemoteDeviceName != "dist-7" ||
		cdp.RemoteManagementAddress != "192.0.2.7" || cdp.RemotePlatform != "C9300" {
		t.Fatalf("CDP evidence = %+v", cdp)
	}
	for _, n := range got {
		if n.TenantID != "tenant-a" || n.AgentID != "agent-a" ||
			n.LocalDeviceAddress != "192.0.2.1" || n.ID == "" {
			t.Fatalf("scope/provenance lost: %+v", n)
		}
	}
}

func TestPollSNMPNeighborsIsExplicitAndBounded(t *testing.T) {
	if got := pollSNMPNeighbors(neighborConn{}, Target{Address: "192.0.2.1"}, "t", "a",
		Inventory{}, time.Now()); len(got) != 0 {
		t.Fatalf("neighbor walks must be opt-in, got %+v", got)
	}
	snapshot := NeighborSnapshot{
		TenantID: "t", AgentID: "a", DeviceAddress: "d", ObservedAt: time.Now(),
	}
	for i := 0; i < MaxNeighborsPerDevice+20; i++ {
		snapshot.Neighbors = append(snapshot.Neighbors, NeighborEvidence{
			LocalPortID: "local", RemoteChassisID: "remote",
			RemotePortID: "port-" + strconv.Itoa(i), Protocol: NeighborProtocolLLDP,
			FreshUntil: snapshot.ObservedAt.Add(48 * time.Hour),
		})
	}
	valid, err := ValidateNeighborSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid.Neighbors) > MaxNeighborsPerDevice {
		t.Fatalf("snapshot grew past cap: %d", len(valid.Neighbors))
	}
	for _, n := range valid.Neighbors {
		if n.FreshUntil.After(n.ObservedAt.Add(time.Hour)) {
			t.Fatalf("untrusted freshness exceeded cap: %+v", n)
		}
	}
}
