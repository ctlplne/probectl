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
}
