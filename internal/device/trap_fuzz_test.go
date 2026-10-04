// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// FuzzSNMPTrapDatagram drives the SNMP trap ingest path — BER/ASN.1 unmarshal,
// source authentication, and normalization — with arbitrary datagrams. A trap
// listener accepts UDP from the network before it knows the sender, so this is
// the least-authenticated byte path in the device plane (Foundation-Loop
// S-7f81b4c2). It must never panic, and an accepted trap must always carry the
// receiver's OWN tenant — a datagram can never assert one.
func FuzzSNMPTrapDatagram(f *testing.F) {
	// A minimal SNMPv2c trap PDU shape plus deliberate malformations.
	f.Add([]byte{0x30, 0x82, 0x00, 0x0B, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63})
	f.Add([]byte{0x30, 0xFF, 0xFF, 0xFF}) // length beyond the datagram
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x00})
	f.Add([]byte{})
	// ING-42: an SNMPv3-shaped datagram (version 3 in the common header) so the
	// fuzzer reaches the USM source-matching and engine/username checks, not just
	// the v2c path. gosnmp's v3 decode is the ING-05 panic surface.
	f.Add([]byte{0x30, 0x0E, 0x02, 0x01, 0x03, 0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x02, 0x05, 0xDC, 0x04, 0x00})
	// ING-42: a COMPLETE, VALID v2c trap for the core-v2c source. Random bytes
	// almost never survive gosnmp's UnmarshalTrap, so without a valid base the
	// fuzzer never reaches authenticate/RecordPacket/handleLivePacket — only the
	// decode gate. Seeding a real datagram lets the mutation engine explore the
	// live record+authenticate path (a planted panic in handleLivePacket is
	// caught within seconds with this seed, never without it).
	if valid, err := (&gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public-core",
		PDUType:   gosnmp.SNMPv2Trap,
		RequestID: 1001,
		Variables: snmpTrapVarBinds("1.3.6.1.6.3.1.1.5.3", 7),
	}).MarshalMsg(); err == nil {
		f.Add(valid)
	}

	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1162}

	f.Fuzz(func(t *testing.T, data []byte) {
		store := NewMemoryTrapStore(8)
		receiver, err := NewTrapReceiver(TrapReceiverConfig{
			TenantID: "tenant-a",
			AgentID:  "device-agent-1",
			Now:      func() time.Time { return now },
			// Multi-source v2c + v3(USM): the datagram is authenticated against a
			// table, so the fuzzer exercises source matching and the v3 USM path.
			Sources: []TrapSource{
				{Name: "core-v2c", Address: "127.0.0.1", Transport: TransportSNMPv2c, Credential: Credential{Community: "public-core"}},
				{Name: "edge-v2c", Address: "127.0.0.2", Transport: TransportSNMPv2c, Credential: Credential{Community: "public-edge"}},
				{Name: "core-v3", Address: "127.0.0.1", Transport: TransportSNMPv3, Credential: Credential{Username: "trap-user", AuthProto: "sha", AuthPass: "auth-password"}},
			},
		}, store)
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
		// Drive the datagram through the LIVE listener's per-packet path:
		// gosnmp's listener unmarshals, then calls OnNewTrap -> handleLivePacket.
		// We mirror that exactly (UnmarshalTrap then handleLivePacket) so the fuzz
		// covers the live decode+record+health path, not a shortcut. Any panic in
		// gosnmp's v3 decode (ING-05) surfaces here.
		pkt, err := receiver.params.UnmarshalTrap(append([]byte(nil), data...), true)
		if err != nil || pkt == nil {
			return
		}
		receiver.handleLivePacket(context.Background(), pkt, remote)
		// A recorded trap must ALWAYS carry the receiver's own tenant — a datagram
		// can never assert one, and nothing may land under another tenant.
		if other := store.listTrapEvents("attacker-tenant"); len(other) != 0 {
			t.Fatalf("a datagram caused a trap under a foreign tenant: %+v", other)
		}
		for _, ev := range store.listTrapEvents("tenant-a") {
			if ev.TenantID != "tenant-a" {
				t.Fatalf("recorded trap carries tenant %q; a datagram must never assert one", ev.TenantID)
			}
		}
	})
}
