// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package canary

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewDNSDefaults(t *testing.T) {
	c, err := NewDNS(Config{Target: "example.com"})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	d := c.(*dnsCanary)
	if d.name != "example.com." {
		t.Errorf("name = %q, want fqdn example.com.", d.name)
	}
	if d.qtype != dns.TypeA {
		t.Errorf("qtype = %d, want A", d.qtype)
	}
	if d.transport != "udp" || d.mode != "resolver" {
		t.Errorf("transport/mode = %s/%s, want udp/resolver", d.transport, d.mode)
	}
	if d.dnssec {
		t.Error("dnssec should default off")
	}
	if d.timeout != 5*time.Second {
		t.Errorf("timeout = %s, want 5s", d.timeout)
	}
	if d.Describe().Type != dnsType {
		t.Errorf("Describe().Type = %q", d.Describe().Type)
	}
}

func TestNewDNSParams(t *testing.T) {
	c, err := NewDNS(Config{
		Target:  "example.com",
		Timeout: 2 * time.Second,
		Params: map[string]string{
			"type":      "mx",
			"transport": "dot",
			"mode":      "trace",
			"dnssec":    "true",
			"server":    "9.9.9.9",
		},
	})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	d := c.(*dnsCanary)
	if d.qtype != dns.TypeMX {
		t.Errorf("qtype = %d, want MX", d.qtype)
	}
	if d.transport != "dot" || d.mode != "trace" || !d.dnssec {
		t.Errorf("got transport=%s mode=%s dnssec=%v", d.transport, d.mode, d.dnssec)
	}
	if d.server != "9.9.9.9" {
		t.Errorf("server = %q", d.server)
	}
	if d.timeout != 2*time.Second {
		t.Errorf("timeout = %s, want 2s", d.timeout)
	}
}

func TestNewDNSDefaultServerPerTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		want      string
	}{
		{"doh", "https://cloudflare-dns.com/dns-query"},
		{"dot", "1.1.1.1:853"},
	} {
		c, err := NewDNS(Config{Target: "example.com", Params: map[string]string{"transport": tc.transport}})
		if err != nil {
			t.Fatalf("NewDNS(%s): %v", tc.transport, err)
		}
		if got := c.(*dnsCanary).server; got != tc.want {
			t.Errorf("default server for %s = %q, want %q", tc.transport, got, tc.want)
		}
	}
}

func TestNewDNSErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty target", Config{Target: "  "}},
		{"bad type", Config{Target: "x.com", Params: map[string]string{"type": "ZZZ"}}},
		{"bad transport", Config{Target: "x.com", Params: map[string]string{"transport": "quic"}}},
		{"bad mode", Config{Target: "x.com", Params: map[string]string{"mode": "recurse"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDNS(tc.cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// signedA builds an A RRset, a DNSKEY, and an RRSIG over the RRset signed by that
// key — an in-memory, signed answer needing no network, so DNSSEC validation is
// exercised against real signatures (not a trusted AD bit).
func signedA(t *testing.T, ip string) (rrset []dns.RR, sig *dns.RRSIG, key *dns.DNSKEY) {
	t.Helper()
	key = &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("generated key is not a crypto.Signer")
	}
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP(ip),
	}
	sig = &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: "example.com.",
	}
	if err := sig.Sign(signer, []dns.RR{a}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return []dns.RR{a}, sig, key
}

func TestVerifyRRSIGSecure(t *testing.T) {
	rrset, sig, key := signedA(t, "93.184.216.34")
	if got := verifyRRSIG(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}); got != dnssecSecure {
		t.Errorf("verifyRRSIG = %q, want secure", got)
	}
}

func TestVerifyRRSIGInsecure(t *testing.T) {
	rrset, _, key := signedA(t, "93.184.216.34")
	// No RRSIGs at all → the zone is unsigned, not a failure.
	if got := verifyRRSIG(rrset, nil, []*dns.DNSKEY{key}); got != dnssecInsecure {
		t.Errorf("verifyRRSIG = %q, want insecure", got)
	}
}

func TestVerifyRRSIGBogusTampered(t *testing.T) {
	rrset, sig, key := signedA(t, "93.184.216.34")
	// Tamper with the signed data after signing → the signature no longer covers
	// the RRset → bogus (NOT silently accepted).
	rrset[0].(*dns.A).A = net.ParseIP("6.6.6.6")
	if got := verifyRRSIG(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}); got != dnssecBogus {
		t.Errorf("verifyRRSIG (tampered) = %q, want bogus", got)
	}
}

func TestVerifyRRSIGBogusExpired(t *testing.T) {
	rrset, sig, key := signedA(t, "93.184.216.34")
	sig.Expiration = uint32(time.Now().Add(-time.Hour).Unix()) // outside validity window
	if got := verifyRRSIG(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}); got != dnssecBogus {
		t.Errorf("verifyRRSIG (expired) = %q, want bogus", got)
	}
}

func TestVerifyRRSIGBogusNoKeys(t *testing.T) {
	rrset, sig, _ := signedA(t, "93.184.216.34")
	if got := verifyRRSIG(rrset, []*dns.RRSIG{sig}, nil); got != dnssecBogus {
		t.Errorf("verifyRRSIG (no keys) = %q, want bogus", got)
	}
}

func TestSplitAnswerAndCount(t *testing.T) {
	rrset, sig, _ := signedA(t, "1.2.3.4")
	msg := new(dns.Msg)
	msg.Answer = append(append([]dns.RR{}, rrset...), sig)

	gotSet, gotSigs := splitAnswer(msg)
	if len(gotSet) != 1 || len(gotSigs) != 1 {
		t.Fatalf("splitAnswer = %d rrs / %d sigs, want 1/1", len(gotSet), len(gotSigs))
	}
	if n := countAnswers(msg); n != 1 {
		t.Errorf("countAnswers = %d, want 1 (RRSIG excluded)", n)
	}
}

func TestSummarizeAnswers(t *testing.T) {
	msg := new(dns.Msg)
	mk := func(ip string) *dns.A {
		return &dns.A{Hdr: dns.RR_Header{Name: "x.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
	}
	msg.Answer = []dns.RR{mk("5.6.7.8"), mk("1.2.3.4")}
	got := summarizeAnswers(msg)
	if got != "A 1.2.3.4, A 5.6.7.8" {
		t.Errorf("summarizeAnswers = %q, want sorted A records", got)
	}
}

func TestAddressHelpers(t *testing.T) {
	if got := withDefaultPort("1.1.1.1", "53"); got != "1.1.1.1:53" {
		t.Errorf("withDefaultPort bare = %q", got)
	}
	if got := withDefaultPort("1.1.1.1:5353", "53"); got != "1.1.1.1:5353" {
		t.Errorf("withDefaultPort with port = %q", got)
	}
	if got := hostOnly("dns.example:853"); got != "dns.example" {
		t.Errorf("hostOnly = %q", got)
	}
	if got := hostOnly("dns.example"); got != "dns.example" {
		t.Errorf("hostOnly no-port = %q", got)
	}
	if boolFloat(true) != 1 || boolFloat(false) != 0 {
		t.Error("boolFloat mapping wrong")
	}
}
