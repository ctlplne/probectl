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

	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1162}

	f.Fuzz(func(t *testing.T, data []byte) {
		receiver, err := NewTrapReceiver(TrapReceiverConfig{
			TenantID: "tenant-a",
			AgentID:  "device-agent-1",
			Now:      func() time.Time { return now },
			Sources: []TrapSource{{
				Name:       "core-v2c",
				Address:    "127.0.0.1",
				Transport:  TransportSNMPv2c,
				Credential: Credential{Community: "public-core"},
			}},
		}, NewMemoryTrapStore(8))
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
		event, _, _, err := receiver.decodeAndRecord(context.Background(), data, remote)
		if err != nil {
			return
		}
		if event.TenantID != "tenant-a" {
			t.Fatalf("accepted trap carries tenant %q; a datagram must never assert one", event.TenantID)
		}
	})
}
