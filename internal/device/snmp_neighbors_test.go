// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type neighborConn struct {
	columns map[string][]gosnmp.SnmpPDU
	errors  map[string]error
}

func (c neighborConn) Get([]string) ([]gosnmp.SnmpPDU, error) { return nil, nil }
func (c neighborConn) Close() error                           { return nil }
func (c neighborConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	if err := c.errors[root]; err != nil {
		return err
	}
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
	got, err := pollSNMPNeighbors(conn, Target{
		Address: "192.0.2.1", Transport: TransportSNMPv3,
		Interval: time.Minute, Neighbors: true,
	}, "tenant-a", "agent-a", inv, now)
	if err != nil {
		t.Fatalf("poll neighbors: %v", err)
	}
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
	got, err := pollSNMPNeighbors(neighborConn{}, Target{Address: "192.0.2.1"}, "t", "a",
		Inventory{}, time.Now())
	if err != nil {
		t.Fatalf("disabled neighbors: %v", err)
	}
	if len(got) != 0 {
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

func TestPollSNMPNeighborsWalkFailureReturnsNoPartialSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	timeout := errors.New("transport timeout")
	conn := neighborConn{
		columns: map[string][]gosnmp.SnmpPDU{
			oidLLDPLocPortID: {
				{Name: oidLLDPLocPortID + ".5", Value: []byte("xe-0/0/5")},
			},
			oidLLDPRemTTL: {
				{Name: oidLLDPRemTTL + ".10.5.1", Value: 120},
			},
		},
		errors: map[string]error{oidLLDPRemChassisID: timeout},
	}

	got, err := pollSNMPNeighbors(conn, Target{
		Address: "192.0.2.1", Interval: time.Minute, Neighbors: true,
	}, "tenant-a", "agent-a", Inventory{}, now)
	if !errors.Is(err, timeout) || !strings.Contains(err.Error(), "lldp remote chassis ID") ||
		!strings.Contains(err.Error(), oidLLDPRemChassisID) {
		t.Fatalf("neighbor walk error = %v", err)
	}
	if got != nil {
		t.Fatalf("partial neighbor evidence escaped failed poll: %+v", got)
	}
}

func TestPollSNMPNeighborsMissingMIBTerminationKeepsSuccessfulProtocolSubset(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	conn := neighborConn{columns: map[string][]gosnmp.SnmpPDU{
		oidLLDPLocPortID: {
			{Name: oidLLDPLocPortID, Type: gosnmp.NoSuchObject},
		},
		oidCDPCacheDeviceID: {
			{Name: oidCDPCacheDeviceID + ".7.1", Value: []byte("dist-7")},
		},
		oidCDPCacheDevicePort: {
			{Name: oidCDPCacheDevicePort + ".7.1", Value: []byte("Gi1/0/48")},
		},
	}}

	got, err := pollSNMPNeighbors(conn, Target{
		Address: "192.0.2.1", Interval: time.Minute, Neighbors: true,
	}, "tenant-a", "agent-a", Inventory{}, now)
	if err != nil {
		t.Fatalf("missing LLDP MIB must be a graceful subset: %v", err)
	}
	if len(got) != 1 || got[0].Protocol != NeighborProtocolCDP ||
		got[0].RemoteDeviceName != "dist-7" {
		t.Fatalf("successful CDP subset = %+v", got)
	}
}

type routedNeighborConn struct {
	snmpConn
	neighbors neighborConn
}

func (c *routedNeighborConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	switch root {
	case oidLLDPLocPortID, oidLLDPLocPortDesc, oidLLDPRemTTL, oidLLDPRemChassisID,
		oidLLDPRemPortID, oidLLDPRemPortDesc, oidLLDPRemSysName, oidLLDPRemSysDesc,
		oidLLDPRemSysCapEnable, oidCDPCacheAddress, oidCDPCacheVersion, oidCDPCacheDeviceID,
		oidCDPCacheDevicePort, oidCDPCachePlatform, oidCDPCacheCapabilities:
		return c.neighbors.BulkWalk(root, fn)
	default:
		return c.snmpConn.BulkWalk(root, fn)
	}
}

type captureNeighborEmitter struct {
	captureEmitter
	neighborMu sync.Mutex
	snapshots  []NeighborSnapshot
	store      NeighborStore
}

func (e *captureNeighborEmitter) EmitNeighbors(ctx context.Context, snapshot NeighborSnapshot) error {
	e.neighborMu.Lock()
	e.snapshots = append(e.snapshots, snapshot)
	e.neighborMu.Unlock()
	if e.store != nil {
		return e.store.ReplaceSnapshot(ctx, snapshot.TenantID, snapshot)
	}
	return nil
}

func (e *captureNeighborEmitter) neighborSnapshot() []NeighborSnapshot {
	e.neighborMu.Lock()
	defer e.neighborMu.Unlock()
	return append([]NeighborSnapshot(nil), e.snapshots...)
}

func TestRuntimeNeighborFailurePreservesPreviousSnapshotAndSuccessfulEmptyClears(t *testing.T) {
	cfg := &Config{TenantID: "tenant-a", AgentID: "agent-a", Devices: []Target{{
		Address: "192.0.2.1", Transport: TransportSNMPv2c, Credential: "ro",
		Interval: time.Minute, Neighbors: true,
	}}}
	store := NewMemoryNeighborStore()
	emitter := &captureNeighborEmitter{store: store}
	var logs bytes.Buffer
	rt, err := New(cfg, emitter, mapCreds{"ro": {Community: "public"}},
		slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	p := func(root, index string, value any) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: root + "." + index, Value: value}
	}
	withNeighbors := neighborConn{columns: map[string][]gosnmp.SnmpPDU{
		oidCDPCacheDeviceID:   {p(oidCDPCacheDeviceID, "1.1", []byte("leaf-1"))},
		oidCDPCacheDevicePort: {p(oidCDPCacheDevicePort, "1.1", []byte("Ethernet1"))},
	}}
	timeout := errors.New("transport timeout")
	failedNeighbors := neighborConn{errors: map[string]error{oidLLDPRemTTL: timeout}}
	emptyNeighbors := neighborConn{}
	polls := []neighborConn{withNeighbors, failedNeighbors, emptyNeighbors}
	rt.dialSNMP = func(_ Target, _ Credential) (snmpConn, error) {
		next := polls[0]
		polls = polls[1:]
		core := &ipWalkConn{
			fakeConn: healthyConn(),
			ipRows:   map[string]uint32{"10.0.0.1": 1},
		}
		return &routedNeighborConn{snmpConn: core, neighbors: next}, nil
	}

	rt.pollOnce(context.Background(), cfg.Devices[0], Credential{Community: "public"})
	rt.pollOnce(context.Background(), cfg.Devices[0], Credential{Community: "public"})
	snapshots := emitter.neighborSnapshot()
	if len(snapshots) != 1 || len(snapshots[0].Neighbors) != 1 {
		t.Fatalf("failed poll replaced previous snapshot: %+v", snapshots)
	}
	rows, _, err := store.ListNeighbors(context.Background(), cfg.TenantID, NeighborFilter{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("stored evidence did not survive failed poll: rows=%+v err=%v", rows, err)
	}
	stats := rt.StatsSnapshot()
	if stats["neighbor_poll_errors"] != 1 || stats["neighbor_snapshots"] != 1 ||
		stats["metrics"] == 0 {
		t.Fatalf("stats after partial poll failure = %+v", stats)
	}
	logged := logs.String()
	if !strings.Contains(logged, "device neighbor poll failed; preserving previous snapshot") ||
		!strings.Contains(logged, "tenant_id=tenant-a") ||
		!strings.Contains(logged, "device=192.0.2.1") ||
		strings.Count(logged, "device neighbor poll failed; preserving previous snapshot") != 1 {
		t.Fatalf("bounded failure log missing scope/context: %q", logged)
	}

	rt.pollOnce(context.Background(), cfg.Devices[0], Credential{Community: "public"})
	snapshots = emitter.neighborSnapshot()
	if len(snapshots) != 2 || len(snapshots[1].Neighbors) != 0 {
		t.Fatalf("successful empty poll did not emit clearing snapshot: %+v", snapshots)
	}
	rows, _, err = store.ListNeighbors(context.Background(), cfg.TenantID, NeighborFilter{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("successful empty poll did not clear stored evidence: rows=%+v err=%v", rows, err)
	}
	if stats := rt.StatsSnapshot(); stats["neighbor_poll_errors"] != 1 ||
		stats["neighbor_snapshots"] != 2 {
		t.Fatalf("stats after successful empty snapshot = %+v", stats)
	}
}
