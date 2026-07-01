// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestSNMPTrapReceiverReplaysV2CV3FixturesTenantScopedAlerts(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	store := NewMemoryTrapStore(10)
	receiver, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		AgentID:  "device-agent-1",
		Now:      func() time.Time { return now },
		Sources: []TrapSource{
			{
				Name:      "core-v2c",
				Address:   "127.0.0.1",
				Transport: TransportSNMPv2c,
				Credential: Credential{
					Community: "public-core",
				},
			},
			{
				Name:      "core-v3",
				Address:   "127.0.0.1",
				Transport: TransportSNMPv3,
				Credential: Credential{
					Username:  "trap-user",
					AuthProto: "sha",
					AuthPass:  "auth-password",
				},
			},
		},
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2162}
	v2c := snmpTrapFixtureV2C(t, "public-core", oidSNMPLinkDown, 7)
	event, alert, inserted, err := receiver.DecodeAndRecord(context.Background(), v2c, remote)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first v2c trap should insert")
	}
	if event.TenantID != "tenant-a" || alert.TenantID != "tenant-a" {
		t.Fatalf("tenant stamping failed: event=%+v alert=%+v", event, alert)
	}
	if event.Kind != "snmp.trap.link_down" || event.Severity != "warning" || event.IfIndex != 7 {
		t.Fatalf("normalized v2c event = %+v", event)
	}
	if alert.EventID != event.ID || alert.Title != "SNMP link down" {
		t.Fatalf("alert row = %+v, event = %+v", alert, event)
	}
	if event.AuthPrincipal != "core-v2c" {
		t.Fatalf("v2c event stored secret community instead of source name: %+v", event)
	}

	if _, _, inserted, err := receiver.DecodeAndRecord(context.Background(), v2c, remote); err != nil || inserted {
		t.Fatalf("duplicate v2c replay inserted=%v err=%v", inserted, err)
	}

	v3 := snmpTrapFixtureV3(t, "trap-user", "auth-password", oidSNMPColdStart, 0)
	event, alert, inserted, err = receiver.DecodeAndRecord(context.Background(), v3, remote)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first v3 trap should insert")
	}
	if event.Version != "snmpv3" || event.AuthPrincipal != "trap-user" || event.Kind == "" {
		t.Fatalf("normalized v3 event = %+v", event)
	}
	if alert.EventID != event.ID || alert.TenantID != "tenant-a" {
		t.Fatalf("v3 alert = %+v", alert)
	}

	if got := len(store.ListTrapEvents("tenant-a")); got != 2 {
		t.Fatalf("tenant-a events = %d, want 2", got)
	}
	if got := len(store.ListTrapAlerts("tenant-a")); got != 2 {
		t.Fatalf("tenant-a alerts = %d, want 2", got)
	}
	if got := len(store.ListTrapEvents("tenant-b")); got != 0 {
		t.Fatalf("tenant-b events = %d, want 0", got)
	}
	if got := len(store.ListTrapAlerts("tenant-b")); got != 0 {
		t.Fatalf("tenant-b alerts = %d, want 0", got)
	}
}

func TestSNMPTrapReceiverRejectsUnauthenticatedFixtures(t *testing.T) {
	store := NewMemoryTrapStore(10)
	receiver, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		Sources: []TrapSource{{
			Name:       "core-v2c",
			Transport:  TransportSNMPv2c,
			Credential: Credential{Community: "public-core"},
		}},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2162}
	if _, _, _, err := receiver.DecodeAndRecord(context.Background(), snmpTrapFixtureV2C(t, "wrong", oidSNMPLinkUp, 7), remote); err == nil {
		t.Fatal("wrong v2c community should fail closed")
	}
	if got := len(store.ListTrapEvents("tenant-a")); got != 0 {
		t.Fatalf("events after rejected trap = %d, want 0", got)
	}
}

func TestSNMPTrapReceiverRequiresAuthenticatedSources(t *testing.T) {
	if _, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		Sources:  []TrapSource{{Name: "no-auth", Transport: TransportSNMPv3, Credential: Credential{Username: "u"}}},
	}, NewMemoryTrapStore(1)); err == nil {
		t.Fatal("snmpv3 trap source without auth pass must fail")
	}
	if _, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		Sources:  []TrapSource{{Name: "bad-v2c", Transport: TransportSNMPv2c}},
	}, NewMemoryTrapStore(1)); err == nil {
		t.Fatal("snmpv2c trap source without community must fail")
	}
}

func snmpTrapFixtureV2C(t *testing.T, community, trapOID string, ifIndex uint32) []byte {
	t.Helper()
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: community,
		PDUType:   gosnmp.SNMPv2Trap,
		RequestID: 1001,
		Variables: snmpTrapVarBinds(trapOID, ifIndex),
	}
	raw, err := packet.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func snmpTrapFixtureV3(t *testing.T, user, authPass, trapOID string, ifIndex uint32) []byte {
	t.Helper()
	capture, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	port := uint16(capture.LocalAddr().(*net.UDPAddr).Port)

	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 user,
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: authPass,
	}
	sender := &gosnmp.GoSNMP{
		Target:             "127.0.0.1",
		Port:               port,
		Version:            gosnmp.Version3,
		Timeout:            time.Second,
		Retries:            0,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           gosnmp.AuthNoPriv,
	}
	if err := sender.Connect(); err != nil {
		t.Fatal(err)
	}
	defer sender.Conn.Close()
	sendErr := make(chan error, 1)
	go func() {
		_, err := sender.SendTrap(gosnmp.SnmpTrap{Variables: snmpTrapVarBinds(trapOID, ifIndex)})
		sendErr <- err
	}()
	if err := capture.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := capture.ReadFromUDP(buf)
	if err != nil {
		select {
		case send := <-sendErr:
			if send != nil {
				t.Fatalf("capture read failed after send error %v: %v", send, err)
			}
		default:
		}
		t.Fatal(err)
	}
	<-sendErr // v3 SendTrap may report a post-send timeout; the datagram is the fixture.
	return append([]byte(nil), buf[:n]...)
}

func snmpTrapVarBinds(trapOID string, ifIndex uint32) []gosnmp.SnmpPDU {
	out := []gosnmp.SnmpPDU{
		{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(12345)},
		{Name: oidSNMPTrapOID0, Type: gosnmp.ObjectIdentifier, Value: trapOID},
	}
	if ifIndex > 0 {
		out = append(out, gosnmp.SnmpPDU{Name: oidIfIndex + "." + strconv.Itoa(int(ifIndex)), Type: gosnmp.Integer, Value: int(ifIndex)})
	}
	return out
}
