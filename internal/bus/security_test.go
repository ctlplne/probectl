// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import "testing"

// getenvOf returns a getenv that resolves exactly one key (others empty).
func getenvOf(key, val string) func(string) string {
	return func(k string) string {
		if k == key {
			return val
		}
		return ""
	}
}

func TestMaxBufferedFromEnv(t *testing.T) {
	if got := MaxBufferedFromEnv(getenvOf("P_MAX_BUFFERED", ""), "P"); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
	if got := MaxBufferedFromEnv(getenvOf("P_MAX_BUFFERED", "123"), "P"); got != 123 {
		t.Errorf("123 = %d, want 123", got)
	}
	if got := MaxBufferedFromEnv(getenvOf("P_MAX_BUFFERED", "12x3"), "P"); got != 0 {
		t.Errorf("non-digit = %d, want 0", got)
	}
	if got := MaxBufferedFromEnv(getenvOf("P_MAX_BUFFERED", "99999999999"), "P"); got != 10_000_000 {
		t.Errorf("overflow = %d, want 10000000", got)
	}
}

func TestSecurityFromEnv(t *testing.T) {
	getenv := func(k string) string {
		switch k {
		case "P_TLS_ENABLED":
			return "true"
		case "P_TLS_CA_FILE":
			return "/ca.pem"
		case "P_TLS_CERT_FILE":
			return "/c.pem"
		case "P_TLS_KEY_FILE":
			return "/k.pem"
		case "P_SASL_MECHANISM":
			return "plain"
		case "P_SASL_USER":
			return "u"
		case "P_SASL_PASSWORD":
			return "p"
		case "P_MAX_BUFFERED":
			return "42"
		default:
			return ""
		}
	}
	s := SecurityFromEnv(getenv, "P")
	if !s.TLSEnabled || s.CAFile != "/ca.pem" || s.CertFile != "/c.pem" || s.KeyFile != "/k.pem" {
		t.Errorf("TLS fields not read: %+v", s)
	}
	if s.SASLMechanism != "plain" || s.SASLUser != "u" || s.SASLPassword != "p" {
		t.Errorf("SASL fields not read: mech=%q user=%q", s.SASLMechanism, s.SASLUser)
	}
	if s.AllowPlaintext {
		t.Error("AllowPlaintext should default to false")
	}
	if s.MaxBufferedRecords != 42 {
		t.Errorf("MaxBufferedRecords = %d, want 42", s.MaxBufferedRecords)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("fully-populated TLS+SASL policy should validate: %v", err)
	}
}

func TestSaslMechanism(t *testing.T) {
	if m, err := (Security{}).saslMechanism(); err != nil || m != nil {
		t.Errorf("empty mechanism: m=%v err=%v, want nil,nil", m, err)
	}
	for _, mech := range []string{"plain", "scram-sha-256", "scram-sha-512", "SCRAM-SHA-512"} {
		m, err := Security{SASLMechanism: mech, SASLUser: "u", SASLPassword: "p"}.saslMechanism()
		if err != nil || m == nil {
			t.Errorf("%s: m=%v err=%v, want non-nil,nil", mech, m, err)
		}
	}
	if _, err := (Security{SASLMechanism: "bogus"}).saslMechanism(); err == nil {
		t.Error("unknown mechanism must error")
	}
}

func TestSecurityTLSConfigHardened(t *testing.T) {
	// TLS on, no CA bundle, no client cert -> hardened client config, no file I/O.
	cfg, err := (Security{TLSEnabled: true}).tlsConfig()
	if err != nil || cfg == nil {
		t.Fatalf("hardened tlsConfig: cfg=%v err=%v", cfg, err)
	}
}

func TestKgoOptsTLSAndSASL(t *testing.T) {
	// MaxBuffered + TLS (hardened, no CA) + SASL plain exercises every kgoOpts
	// branch without a broker or cert files.
	opts, err := Security{TLSEnabled: true, SASLMechanism: "plain", SASLUser: "u", SASLPassword: "p", MaxBufferedRecords: 7}.kgoOpts()
	if err != nil {
		t.Fatalf("kgoOpts: %v", err)
	}
	if len(opts) != 3 {
		t.Errorf("opts = %d, want 3 (maxbuffered + tls + sasl)", len(opts))
	}
}
