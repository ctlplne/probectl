// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"strings"
	"testing"
)

// TestConfigArchiveRedactionING07 is the ING-07 regression (G7-6: secrets are
// never stored or exported in the clear). The device config-archive redactor
// historically matched only a keyword set
// (password|secret|community|private-key|api[_-]?key|token), so seven common
// credential syntaxes were stored and exported verbatim. Those seven lines are
// the finding's corpus and are ported here (plus a broader corpus and benign
// controls). For every line the secret VALUE must be gone after RedactConfig,
// while the directive structure around it stays readable, and benign lines are
// left untouched.
//
// The secret tokens below deliberately contain no English word from the old
// keyword set, so on the pre-fix matcher these lines are not touched at all and
// the secret survives — which is exactly what makes this assertion-RED on the
// vulnerable code and GREEN on the fixed `configRedactRules` matcher.
func TestConfigArchiveRedactionING07(t *testing.T) {
	type redCase struct {
		name    string
		line    string
		secrets []string // every one must be gone from the output
		keep    string   // a non-secret token that must survive (structure stays useful)
	}

	// The seven syntaxes the finding proved SURVIVED the keyword-only redactor.
	// Secret tokens carry no keyword-set word, so each survives on the old
	// matcher (true RED) and must be masked by the new one (GREEN).
	ing07Survivors := []redCase{
		{"tacacs-server key", "tacacs-server key TAC5haredK9", []string{"TAC5haredK9"}, "tacacs-server key"},
		{"radius-server key", "radius-server key RAD5haredK9", []string{"RAD5haredK9"}, "radius-server key"},
		{"crypto isakmp key", "crypto isakmp key IS4kmpPSKv1 address 203.0.113.9", []string{"IS4kmpPSKv1"}, "address 203.0.113.9"},
		{"ntp authentication-key md5", "ntp authentication-key 1 md5 NtpMd5V4lue", []string{"NtpMd5V4lue"}, "authentication-key 1 md5"},
		{"snmpv3 auth+priv", "snmp-server user ops ro v3 auth sha Au7hP4ssV3 priv aes 128 Pr1vP4ssV3", []string{"Au7hP4ssV3", "Pr1vP4ssV3"}, "snmp-server user ops ro v3"},
		{"pre-shared-key direct", "pre-shared-key PSKdir3ctV1", []string{"PSKdir3ctV1"}, "pre-shared-key"},
		{"junos $9$ authentication-key", `set protocols bgp group ebgp authentication-key "$9$AbcDEF123xyz"`, []string{"$9$AbcDEF123xyz", "AbcDEF123xyz"}, "authentication-key"},
	}

	// The three lines the finding noted were ALREADY caught by the keyword set
	// (they literally contain password/secret/community). They must stay caught.
	ing07AlreadyCaught := []redCase{
		{"username password 7", "username netadmin password 7 070C285F4D06", []string{"070C285F4D06"}, "username netadmin"},
		{"enable secret 5 hash", "enable secret 5 $1$mERr$Hx5rVt7rPNoHashX", []string{"$1$mERr$Hx5rVt7rPNoHashX", "Hx5rVt7rPNoHashX"}, "enable secret"},
		{"snmp community RO", "snmp-server community Pr1v4t3C0mm RO", []string{"Pr1v4t3C0mm"}, "snmp-server community"},
	}

	// Broader corpus: additional real credential syntaxes across Cisco IOS/NX-OS,
	// Junos and Arista EOS. None carry a keyword-set word in the secret, so each
	// also exercises the extended matcher rather than the old keyword fallback.
	broaderCorpus := []redCase{
		{"key-chain key-string", " key-string MyKeyStr1ngV2", []string{"MyKeyStr1ngV2"}, "key-string"},
		{"ospf authentication-key", " ip ospf authentication-key 0 OspfAuthV3", []string{"OspfAuthV3"}, "authentication-key"},
		{"ospf message-digest-key", " ip ospf message-digest-key 1 md5 OspfMd5V4", []string{"OspfMd5V4"}, "message-digest-key 1 md5"},
		{"tacacs named-block key 7", "tacacs server TAC-1\n address ipv4 192.0.2.11\n key 7 00071A150754", []string{"00071A150754"}, "tacacs server TAC-1"},
		{"radius host key 7 w/ options", "radius-server host 10.0.0.1 auth-port 1812 key 7 09604F0B1A08", []string{"09604F0B1A08"}, "radius-server host 10.0.0.1"},
		{"wpa-psk", "wpa-psk ascii 0 MyWifiV5xx", []string{"MyWifiV5xx"}, "wpa-psk"},
		{"ikev2 psk local scope", " pre-shared-key local LocalPskV6", []string{"LocalPskV6"}, "pre-shared-key local"},
		{"ikev2 psk remote scope", " pre-shared-key remote RemotePskV7", []string{"RemotePskV7"}, "pre-shared-key remote"},
		{"ikev1 keyring psk after 2nd key", "pre-shared-key address 203.0.113.1 key KeyringPskV8", []string{"KeyringPskV8"}, "pre-shared-key"},
		{"snmp trap-host community", "snmp-server host 10.0.0.1 traps HostCommV9", []string{"HostCommV9"}, "snmp-server host 10.0.0.1"},
		{"nxos snmpv3 priv aes-256", "snmp-server user admin network-admin auth sha256 NxAuthVA priv aes-256 NxPrivVB", []string{"NxAuthVA", "NxPrivVB"}, "priv aes-256"},
		{"junos encrypted-password $6$", `set system login user a authentication encrypted-password "$6$roundsHashVC"`, []string{"$6$roundsHashVC", "roundsHashVC"}, "encrypted-password"},
		{"hsrp authentication bare", " standby 1 authentication HsrpPlainVD", []string{"HsrpPlainVD"}, "standby 1 authentication"},
		{"nhrp dmvpn authentication", " ip nhrp authentication NhrpTunVE", []string{"NhrpTunVE"}, "ip nhrp authentication"},
		{"ospfv3 ipsec md5 hex", "ipv6 ospf authentication ipsec spi 500 md5 1234567890ABCDEF1234567890ABCDEF", []string{"1234567890ABCDEF1234567890ABCDEF"}, "ipsec spi 500 md5"},
	}

	run := func(t *testing.T, cs []redCase) {
		t.Helper()
		for _, c := range cs {
			t.Run(c.name, func(t *testing.T) {
				out := RedactConfig(c.line)
				for _, s := range c.secrets {
					if strings.Contains(out, s) {
						t.Errorf("ING-07: secret %q SURVIVED redaction\n  in:  %q\n  out: %q", s, c.line, out)
					}
				}
				if !strings.Contains(out, "[redacted]") {
					t.Errorf("ING-07: nothing was redacted in %q -> %q", c.line, out)
				}
				if c.keep != "" && !strings.Contains(out, c.keep) {
					t.Errorf("ING-07: directive context %q was lost (redact the value, not the whole line)\n  out: %q", c.keep, out)
				}
			})
		}
	}

	t.Run("finding_survivors", func(t *testing.T) { run(t, ing07Survivors) })
	t.Run("finding_already_caught", func(t *testing.T) { run(t, ing07AlreadyCaught) })
	t.Run("broader_corpus", func(t *testing.T) { run(t, broaderCorpus) })

	// Whole-blob archive round-trip through the REAL entry point applied at
	// ops.go ArchiveConfig (RedactConfig on the stored Content): no secret token
	// may survive in the at-rest copy, and benign structure must remain.
	t.Run("archive_entrypoint_whole_blob", func(t *testing.T) {
		var b strings.Builder
		var allSecrets []string
		for _, c := range append(append(append([]redCase{}, ing07Survivors...), ing07AlreadyCaught...), broaderCorpus...) {
			b.WriteString(c.line)
			b.WriteByte('\n')
			allSecrets = append(allSecrets, c.secrets...)
		}
		b.WriteString("hostname core-rtr-01\ninterface GigabitEthernet0/0\n no shutdown\n")

		store := NewMemoryOpsStore()
		got, err := store.ArchiveConfig(context.Background(), ConfigVersion{TenantID: "t-ing07", Device: "core-rtr-01", Content: b.String()})
		if err != nil {
			t.Fatalf("ArchiveConfig: %v", err)
		}
		for _, s := range allSecrets {
			if strings.Contains(got.Content, s) {
				t.Errorf("ING-07: secret %q SURVIVED in the archived (at-rest) config", s)
			}
		}
		if !strings.Contains(got.Content, "hostname core-rtr-01") ||
			!strings.Contains(got.Content, "interface GigabitEthernet0/0") ||
			!strings.Contains(got.Content, "no shutdown") {
			t.Errorf("ING-07: benign config lines were lost in the archive:\n%s", got.Content)
		}
	})

	// False-positive control: lines with no credential must pass through
	// byte-for-byte. A security-first redactor may over-mask a bare token after
	// the literal word "password"/"secret" (documented WEB-03 trade-off), so the
	// controls here avoid those keywords and assert exact preservation.
	t.Run("benign_lines_preserved", func(t *testing.T) {
		benign := []string{
			"hostname core-rtr-01",
			"interface GigabitEthernet0/0",
			" no shutdown",
			" ip address 10.0.0.1 255.255.255.0",
			"ntp server 10.0.0.1",
			" description Uplink to core-agg-1",
			"snmp-server location DC1-row4",
			" key chain OSPF-KC",
			" key 1",
		}
		for _, line := range benign {
			if out := RedactConfig(line); out != line {
				t.Errorf("benign line was mangled:\n  in:  %q\n  out: %q", line, out)
			}
		}
	})
}
