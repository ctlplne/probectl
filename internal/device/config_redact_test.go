// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"strings"
	"testing"
)

// TestRedactConfigVendorSecrets is the WEB-03 regression: the keyword-only
// redactor stored and showed TACACS/RADIUS keys, key-chain key-strings,
// routing-protocol auth keys, IPsec/ISAKMP pre-shared keys, and SNMPv3 auth/priv
// passwords in clear. Each listed secret form must be gone after RedactConfig,
// while the surrounding directive/structure survives.
func TestRedactConfigVendorSecrets(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		secret string
		keep   string // a non-secret token that must survive
	}{
		{"tacacs type-7", "tacacs-server key 7 0822455D0A16TACACSKEY", "0822455D0A16TACACSKEY", "tacacs-server key"},
		{"radius key", "radius-server key MyRadiusKey99", "MyRadiusKey99", "radius-server key"},
		{"key-chain key-string", " key-string MyKeyString123", "MyKeyString123", "key-string"},
		{"isakmp psk", "crypto isakmp key IsakmpPSK123 address 0.0.0.0", "IsakmpPSK123", "address 0.0.0.0"},
		{"pre-shared-key", " pre-shared-key PSKvalue456", "PSKvalue456", "pre-shared-key"},
		{"pre-shared-key ascii quoted", `pre-shared-key ascii-text "QuotedPSK789"`, "QuotedPSK789", "pre-shared-key"},
		{"ospf auth-key", " ip ospf authentication-key OspfAuthKey789", "OspfAuthKey789", "authentication-key"},
		{"ospf md5", " ip ospf message-digest-key 1 md5 OspfMd5Key000", "OspfMd5Key000", "message-digest-key 1 md5"},
		{"snmpv3 auth+priv", "snmp-server user u1 g1 v3 auth sha AuthPass111 priv aes 128 PrivPass222", "AuthPass111", "snmp-server user u1 g1 v3"},
		{"snmpv3 priv", "snmp-server user u1 g1 v3 auth sha AuthPass111 priv aes 128 PrivPass222", "PrivPass222", "auth sha"},
		{"community", "snmp-server community Pr1vateC0mm RO", "Pr1vateC0mm", "RO"},
		{"ios enable secret 5", "enable secret 5 $1$abcd$EncLocalHash", "$1$abcd$EncLocalHash", "enable secret"},
		{"username password 7", "username admin password 7 070C285F4D06", "070C285F4D06", "username admin password"},
		{"junos secret quoted", `set system login user a authentication encrypted-password "$6$roundsSecret"`, "$6$roundsSecret", "encrypted-password"},
		{"ntp auth-key md5", "ntp authentication-key 1 md5 NtpSecretKey", "NtpSecretKey", "authentication-key 1 md5"},
		{"ntp auth-key hex+type", "ntp authentication-key 1 md5 06120A2D40031D1E 7", "06120A2D40031D1E", "authentication-key 1 md5"},
		{"ikev2 psk local", " pre-shared-key local LocalKey123", "LocalKey123", "pre-shared-key local"},
		{"ikev2 psk remote", " pre-shared-key remote RemoteKey456", "RemoteKey456", "pre-shared-key remote"},
		{"wpa psk", "wpa-psk ascii 0 MyWifiPass1", "MyWifiPass1", "wpa-psk"},
		{"snmp trap-host community", "snmp-server host 10.0.0.1 traps HostCommunity9", "HostCommunity9", "snmp-server host 10.0.0.1"},
		{"snmp trap-host version vrf", "snmp-server host 10.0.0.1 version 2c vrf mgmt CommVrfX", "CommVrfX", "snmp-server host 10.0.0.1"},
		{"radius named-block key 7", "radius server RAD-1\n address ipv4 192.0.2.10 auth-port 1812\n key 7 070C285F4D06", "070C285F4D06", "radius server RAD-1"},
		{"tacacs named-block key 7", "tacacs server TAC-1\n address ipv4 192.0.2.11\n key 7 00071A150754", "00071A150754", "tacacs server TAC-1"},
		{"tacacs host cleartext key", "tacacs-server host 10.0.0.1 key MyClearTacKey", "MyClearTacKey", "tacacs-server host 10.0.0.1"},
		{"radius host key 7 w/ options", "radius-server host 10.0.0.1 auth-port 1812 key 7 09604F0B1A08", "09604F0B1A08", "radius-server host 10.0.0.1"},
		{"ospfv3 ipsec md5", "ipv6 ospf authentication ipsec spi 500 md5 1234567890ABCDEF1234567890ABCDEF", "1234567890ABCDEF1234567890ABCDEF", "ipsec spi 500 md5"},
		{"nxos snmpv3 priv aes-128", "snmp-server user admin network-admin auth sha NxAuthPass333 priv aes-128 NxPrivPass444", "NxPrivPass444", "priv aes-128"},
		{"nxos snmpv3 priv aes-256", "snmp-server user admin network-admin auth sha256 NxAuth5 priv aes-256 NxPriv6", "NxPriv6", "priv aes-256"},
		{"ikev1 keyring psk address", "pre-shared-key address 203.0.113.1 key MyKeyringPSK123", "MyKeyringPSK123", "pre-shared-key"},
		{"ikev1 keyring psk hostname", "pre-shared-key hostname peer.example.net key HostKeyPSK456", "HostKeyPSK456", "pre-shared-key"},
		{"snmpv3 auth sha-256 hyphen", "snmp-server user u g v3 auth sha-256 HyphAuthPass priv aes-128 HyphPrivPass", "HyphAuthPass", "auth sha-256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := RedactConfig(c.line)
			if strings.Contains(out, c.secret) {
				t.Errorf("secret %q survived redaction:\n  in:  %q\n  out: %q", c.secret, c.line, out)
			}
			if c.keep != "" && !strings.Contains(out, c.keep) {
				t.Errorf("non-secret context %q was lost (redact the value, not the whole line):\n  out: %q", c.keep, out)
			}
			if !strings.Contains(out, "[redacted]") {
				t.Errorf("nothing was redacted in %q -> %q", c.line, out)
			}
		})
	}

	// Whole-config round-trip: no secret substring survives, structure remains.
	cfg := ""
	for _, c := range cases {
		cfg += c.line + "\n"
	}
	cfg += "interface GigabitEthernet0/0\n no shutdown\n"
	out := RedactConfig(cfg)
	for _, c := range cases {
		if strings.Contains(out, c.secret) {
			t.Errorf("secret %q from %q survived in the whole-config redaction", c.secret, c.name)
		}
	}
	if !strings.Contains(out, "interface GigabitEthernet0/0") || !strings.Contains(out, "no shutdown") {
		t.Error("non-secret config lines were lost")
	}

	// A key-chain key IDENTIFIER (`key 1`, alone on its line) is NOT a secret and
	// must survive; the secret is the following key-string, which must be masked.
	chain := "key chain OSPF-KC\n key 1\n  key-string 7 06120A2D4003\n"
	kc := RedactConfig(chain)
	if !strings.Contains(kc, "key chain OSPF-KC") || !strings.Contains(kc, "key 1\n") {
		t.Errorf("key-chain structure (chain name / key id) was destroyed: %q", kc)
	}
	if strings.Contains(kc, "06120A2D4003") {
		t.Errorf("key-chain key-string secret survived: %q", kc)
	}
}
