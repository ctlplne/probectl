// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// forgedAnswer builds a forged A answer (6.6.6.6) signed by a self-made,
// non-anchored DNSKEY, and ships that key in the response's Additional (Extra)
// section — the exact PoC for ING-09: an attacker who controls the response
// forges a record and attaches the key that "proves" it. Nothing here chains to
// a root trust anchor.
func forgedAnswer(t *testing.T) *dns.Msg {
	t.Helper()
	rrset, sig, key := signedA(t, "6.6.6.6")
	msg := new(dns.Msg)
	msg.Answer = append(append([]dns.RR{}, rrset...), sig)
	msg.Extra = append(msg.Extra, key) // attacker-supplied key in Additional
	return msg
}

// TestValidateDNSSECForgedResponseKeyNeverSecure is the ING-09 regression. A
// forged answer signed by a self-made key, with that key placed in the response
// (Answer/Extra), must NEVER be reported "secure": validateDNSSEC must not trust
// keys from the response (G7-10), and without a reachable zone DNSKEY it falls
// to bogus. This test uses only pre-existing symbols so it compiles against the
// pre-fix baseline, where it FAILS (the forged answer is reported "secure") —
// a true assertion-RED.
func TestValidateDNSSECForgedResponseKeyNeverSecure(t *testing.T) {
	msg := forgedAnswer(t)
	// 127.0.0.1:1 is a refused port: any DNSKEY fetch from the resolver fails
	// fast, so the only key available is the attacker's one in the response.
	c := &dnsCanary{server: "127.0.0.1:1", transport: "tcp", timeout: 2 * time.Second}

	if got := validateDNSSEC(context.Background(), c, msg); got == dnssecSecure {
		t.Fatalf("forged answer signed by a self-made, non-anchored key reported %q — a response-supplied key must never yield secure (ING-09, G7-10)", got)
	}
}

// TestValidateDNSSECUnanchoredNeverSecure pins the honest status surface: a
// signature that verifies against an unanchored (zone self-published) key is
// indeterminate, never secure; a key present only in the response Extra is never
// trusted. The DNSKEY source is injected so no network is needed.
func TestValidateDNSSECUnanchoredNeverSecure(t *testing.T) {
	ctx := context.Background()

	t.Run("legit signature, honest resolver -> indeterminate (not secure)", func(t *testing.T) {
		rrset, sig, key := signedA(t, "93.184.216.34")
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		c := &dnsCanary{fetchKeys: func(context.Context, string) (*dns.Msg, error) {
			km := new(dns.Msg)
			km.Answer = []dns.RR{key} // the zone's self-published key, unanchored
			return km, nil
		}}
		if got := validateDNSSEC(ctx, c, msg); got != dnssecIndeterminate {
			t.Fatalf("validateDNSSEC = %q, want indeterminate — a verified but unanchored signature must not be secure", got)
		}
	})

	t.Run("forged answer, malicious resolver serves the forging key -> indeterminate (never secure)", func(t *testing.T) {
		rrset, sig, key := signedA(t, "6.6.6.6") // forged rdata
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		msg.Extra = append(msg.Extra, key)
		// Even when the resolver colludes and serves the very key that signed the
		// forged answer, the signature verifies — yet without a DS chain to a trust
		// anchor we must NOT call it secure. indeterminate is the honest ceiling.
		c := &dnsCanary{fetchKeys: func(context.Context, string) (*dns.Msg, error) {
			km := new(dns.Msg)
			km.Answer = []dns.RR{key}
			return km, nil
		}}
		got := validateDNSSEC(ctx, c, msg)
		if got == dnssecSecure {
			t.Fatalf("forged answer reported secure — a single valid signature against a non-anchored key is not a chain of trust (ING-09)")
		}
		if got != dnssecIndeterminate {
			t.Fatalf("validateDNSSEC = %q, want indeterminate", got)
		}
	})

	t.Run("key only in response Extra is not trusted -> bogus", func(t *testing.T) {
		rrset, sig, key := signedA(t, "6.6.6.6")
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		msg.Extra = append(msg.Extra, key) // the ONLY copy of the verifying key
		// Honest resolver has no such key (zone unsigned / different key). The
		// response-Extra key must be ignored, leaving nothing that verifies.
		c := &dnsCanary{fetchKeys: func(context.Context, string) (*dns.Msg, error) {
			return new(dns.Msg), nil
		}}
		if got := validateDNSSEC(ctx, c, msg); got != dnssecBogus {
			t.Fatalf("validateDNSSEC = %q, want bogus — a key taken only from the Additional section must not be trusted (G7-10)", got)
		}
	})
}

// mintZone builds a fully, correctly delegated DNSSEC zone in-process (no
// network): a key-signing key (KSK, the DS entry point) and a zone-signing key
// (ZSK); the KSK self-signs the DNSKEY RRset {KSK, ZSK}; the ZSK signs an A
// answer; and the matching DS over the KSK is returned to be configured as a
// trust anchor. This is the real chain a parent-DS -> child-DNSKEY delegation
// gives validateDNSSEC. All crypto routes through miekg/dns (docs/guardrails.md
// G7-3).
func mintZone(t *testing.T, zone, ip string) (answer, keyset *dns.Msg, ds *dns.DS) {
	t.Helper()
	zone = dns.Fqdn(zone)

	ksk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, // SEP: key-signing key
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	kskPriv, err := ksk.Generate(256)
	if err != nil {
		t.Fatalf("ksk Generate: %v", err)
	}
	zsk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256, // zone-signing key
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	zskPriv, err := zsk.Generate(256)
	if err != nil {
		t.Fatalf("zsk Generate: %v", err)
	}

	incep := uint32(time.Now().Add(-time.Hour).Unix())
	expir := uint32(time.Now().Add(time.Hour).Unix())

	// KSK self-signs the DNSKEY RRset, binding the ZSK to the anchored KSK.
	keySig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		Inception:  incep,
		Expiration: expir,
		KeyTag:     ksk.KeyTag(),
		SignerName: zone,
	}
	if err := keySig.Sign(kskPriv.(crypto.Signer), []dns.RR{ksk, zsk}); err != nil {
		t.Fatalf("sign DNSKEY RRset: %v", err)
	}

	// ZSK signs the answer.
	a := &dns.A{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP(ip),
	}
	aSig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		Inception:  incep,
		Expiration: expir,
		KeyTag:     zsk.KeyTag(),
		SignerName: zone,
	}
	if err := aSig.Sign(zskPriv.(crypto.Signer), []dns.RR{a}); err != nil {
		t.Fatalf("sign A: %v", err)
	}

	answer = new(dns.Msg)
	answer.Answer = []dns.RR{a, aSig}
	keyset = new(dns.Msg)
	keyset.Answer = []dns.RR{ksk, zsk, keySig}
	ds = ksk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}
	return answer, keyset, ds
}

func fixedKeyset(ks *dns.Msg) func(context.Context, string) (*dns.Msg, error) {
	return func(context.Context, string) (*dns.Msg, error) { return ks, nil }
}

// tamperAnswerRRSIG corrupts the answer's RRSIG signature in place (a valid
// base64 character swap), so the chain still anchors but the answer signature no
// longer verifies.
func tamperAnswerRRSIG(t *testing.T, msg *dns.Msg) {
	t.Helper()
	for _, rr := range msg.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.Signature == "" {
			continue
		}
		repl := byte('A')
		if sig.Signature[0] == 'A' {
			repl = 'B'
		}
		sig.Signature = string(repl) + sig.Signature[1:]
		return
	}
	t.Fatal("no answer RRSIG to tamper")
}

// TestValidateDNSSECAnchorChain is the RT-01 regression, driven through the real
// validateDNSSEC path. The signal is honest only if "secure" requires a chain to
// a configured trust anchor:
//  1. a self-signed zone minted by an attacker, not chaining to the configured
//     anchor, is NEVER "secure" (it is indeterminate) — the RT-01 lie;
//  2. a zone whose KSK is pinned by the configured anchor is "secure";
//  3. a tampered answer RRSIG is "bogus".
//
// Non-vacuity: reverting only the anchoredKeyset enforcement in validateDNSSEC
// (promoting any verified signature straight to "secure") makes subtest (1) fail
// with got=secure — exactly the RT-01 behavior.
func TestValidateDNSSECAnchorChain(t *testing.T) {
	ctx := context.Background()
	goodAnswer, goodKeyset, goodDS := mintZone(t, "example.com.", "93.184.216.34")

	t.Run("unanchored attacker zone -> never secure", func(t *testing.T) {
		// The attacker mints their own key and forges an A record. Their keyset
		// does not chain to the legitimate anchor (goodDS).
		forgedAnswer, forgedKeyset, _ := mintZone(t, "example.com.", "6.6.6.6")
		c := &dnsCanary{
			trustAnchors: []*dns.DS{goodDS}, // the legitimate anchor
			fetchKeys:    fixedKeyset(forgedKeyset),
		}
		got := validateDNSSEC(ctx, c, forgedAnswer)
		if got == dnssecSecure {
			t.Fatalf("forged answer from an unanchored self-signed key reported %q — a zone that does not chain to the trust anchor must never be secure (RT-01, G7-9/G7-10)", got)
		}
		if got != dnssecIndeterminate && got != dnssecBogus {
			t.Fatalf("validateDNSSEC = %q, want indeterminate or bogus", got)
		}
	})

	t.Run("anchored zone -> secure", func(t *testing.T) {
		c := &dnsCanary{
			trustAnchors: []*dns.DS{goodDS},
			fetchKeys:    fixedKeyset(goodKeyset),
		}
		if got := validateDNSSEC(ctx, c, goodAnswer); got != dnssecSecure {
			t.Fatalf("validateDNSSEC = %q, want secure — a zone whose KSK chains to the configured trust anchor is authentic", got)
		}
	})

	t.Run("tampered answer RRSIG -> bogus", func(t *testing.T) {
		answer, keyset, ds := mintZone(t, "example.com.", "93.184.216.34")
		tamperAnswerRRSIG(t, answer)
		c := &dnsCanary{
			trustAnchors: []*dns.DS{ds},
			fetchKeys:    fixedKeyset(keyset),
		}
		if got := validateDNSSEC(ctx, c, answer); got != dnssecBogus {
			t.Fatalf("validateDNSSEC = %q, want bogus — a tampered RRSIG must fail verification", got)
		}
	})
}
