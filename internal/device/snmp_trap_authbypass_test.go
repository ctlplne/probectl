// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func oneV3Receiver(t *testing.T) *TrapReceiver {
	t.Helper()
	r, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		Sources: []TrapSource{{
			Name: "core", Transport: TransportSNMPv3, Address: "127.0.0.1",
			Credential: Credential{Username: "trap-user", AuthProto: "sha", AuthPass: "auth-password"},
		}},
	}, NewMemoryTrapStore(16))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ING-04: gosnmp's live trap listener decodes with UnmarshalTrap(msg,false),
// which on the single-source path keys authentication on the LISTENER's
// MsgFlags. They were never set, so the HMAC was never checked and a trap
// signed with the wrong key was accepted. The listener must now verify it.
func TestSNMPv3LiveListenerVerifiesHMAC(t *testing.T) {
	r := oneV3Receiver(t)
	correct := snmpTrapFixtureV3(t, "trap-user", "auth-password", oidSNMPColdStart, 0)
	wrong := snmpTrapFixtureV3(t, "trap-user", "the-wrong-password", oidSNMPColdStart, 0)

	// The live listener path.
	if _, err := r.params.UnmarshalTrap(append([]byte(nil), correct...), false); err != nil {
		t.Fatalf("correctly-signed trap must decode on the live path: %v", err)
	}
	if _, err := r.params.UnmarshalTrap(append([]byte(nil), wrong...), false); err == nil {
		t.Fatal("a wrong-key v3 trap must be refused by the live listener (ING-04)")
	}
}

// ING-04: every configured source has auth credentials, so a noAuthNoPriv trap
// (whose HMAC gosnmp never verifies) must be refused outright by the receiver.
func TestSNMPv3TrapReceiverRejectsNoAuthNoPriv(t *testing.T) {
	r := oneV3Receiver(t)
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           gosnmp.NoAuthNoPriv, // forged: no authentication
		SecurityModel:      gosnmp.UserSecurityModel,
		PDUType:            gosnmp.SNMPv2Trap,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "trap-user"},
		Variables:          snmpTrapVarBinds(oidSNMPColdStart, 0),
	}
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	if _, _, _, err := r.RecordPacket(context.Background(), pkt, remote); err == nil || !errors.Is(err, ErrTrapRejected) {
		t.Fatalf("noAuthNoPriv trap must be rejected (ING-04); got err=%v", err)
	}
}

// ING-04 (bypass closed): gosnmp skips HMAC verification for its "engine
// discovery" case — an empty USM username + empty authoritative engine id — and
// the receiver's old empty-username single-source fallback then laundered such a
// forged datagram into the lone configured source as authenticated. A v3 trap
// must now carry a non-empty username that matches a source and a non-empty
// engine id; nothing else is trusted.
func TestSNMPv3TrapReceiverRejectsUnverifiableV3(t *testing.T) {
	r := oneV3Receiver(t)
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	cases := []struct {
		name string
		pkt  *gosnmp.SnmpPacket
	}{
		{"empty username (engine-discovery HMAC skip)", &gosnmp.SnmpPacket{
			Version: gosnmp.Version3, MsgFlags: gosnmp.AuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
			PDUType:            gosnmp.SNMPv2Trap,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "", AuthoritativeEngineID: ""},
			Variables:          snmpTrapVarBinds(oidSNMPColdStart, 0),
		}},
		{"nil security parameters", &gosnmp.SnmpPacket{
			Version: gosnmp.Version3, MsgFlags: gosnmp.AuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
			PDUType: gosnmp.SNMPv2Trap, Variables: snmpTrapVarBinds(oidSNMPColdStart, 0),
		}},
		{"matching username but empty engine id", &gosnmp.SnmpPacket{
			Version: gosnmp.Version3, MsgFlags: gosnmp.AuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
			PDUType:            gosnmp.SNMPv2Trap,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "trap-user", AuthoritativeEngineID: ""},
			Variables:          snmpTrapVarBinds(oidSNMPColdStart, 0),
		}},
		// gosnmp only runs HMAC verification for the USM security model; any
		// other model is decoded unverified but still parses a username/engine id.
		{"non-USM security model (gosnmp skips verification)", &gosnmp.SnmpPacket{
			Version: gosnmp.Version3, MsgFlags: gosnmp.AuthNoPriv, SecurityModel: 0,
			PDUType:            gosnmp.SNMPv2Trap,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "trap-user", AuthoritativeEngineID: snmpTrapFixtureEngineID},
			Variables:          snmpTrapVarBinds(oidSNMPColdStart, 0),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := r.RecordPacket(context.Background(), tc.pkt, remote); err == nil || !errors.Is(err, ErrTrapRejected) {
				t.Fatalf("unverifiable v3 trap must be rejected (ING-04); got err=%v", err)
			}
		})
	}
}

// ING-05: with more than one v3 source the listener params left
// SecurityParameters nil (only the table was set); gosnmp's listenUDP then
// dereferenced it on the first v3 trap and panicked the whole device agent.
// The params must keep a non-nil SecurityParameters template.
func TestSNMPv3TwoSourceParamsKeepNonNilSecurityParameters(t *testing.T) {
	r, err := NewTrapReceiver(TrapReceiverConfig{
		TenantID: "tenant-a",
		Sources: []TrapSource{
			{Name: "r1", Transport: TransportSNMPv3, Address: "127.0.0.1",
				Credential: Credential{Username: "u1", AuthProto: "sha", AuthPass: "passphrase-one"}},
			{Name: "r2", Transport: TransportSNMPv3, Address: "127.0.0.2",
				Credential: Credential{Username: "u2", AuthProto: "sha", AuthPass: "passphrase-two"}},
		},
	}, NewMemoryTrapStore(16))
	if err != nil {
		t.Fatal(err)
	}
	if r.params.SecurityParameters == nil {
		t.Fatal("two-source v3 listener left SecurityParameters nil — gosnmp listenUDP would panic (ING-05)")
	}
}
