// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
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
// rrsig-only, never secure; a key present only in the response Extra is never
// trusted. The DNSKEY source is injected so no network is needed.
func TestValidateDNSSECUnanchoredNeverSecure(t *testing.T) {
	ctx := context.Background()

	t.Run("legit signature, honest resolver -> rrsig-only (not secure)", func(t *testing.T) {
		rrset, sig, key := signedA(t, "93.184.216.34")
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		c := &dnsCanary{fetchKeys: func(context.Context, string) ([]*dns.DNSKEY, error) {
			return []*dns.DNSKEY{key}, nil // the zone's self-published key, unanchored
		}}
		if got := validateDNSSEC(ctx, c, msg); got != dnssecRRSIGOnly {
			t.Fatalf("validateDNSSEC = %q, want rrsig-only — a verified but unanchored signature must not be secure", got)
		}
	})

	t.Run("forged answer, malicious resolver serves the forging key -> rrsig-only (never secure)", func(t *testing.T) {
		rrset, sig, key := signedA(t, "6.6.6.6") // forged rdata
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		msg.Extra = append(msg.Extra, key)
		// Even when the resolver colludes and serves the very key that signed the
		// forged answer, the signature verifies — yet without a DS chain to the
		// root we must NOT call it secure. rrsig-only is the honest ceiling.
		c := &dnsCanary{fetchKeys: func(context.Context, string) ([]*dns.DNSKEY, error) {
			return []*dns.DNSKEY{key}, nil
		}}
		got := validateDNSSEC(ctx, c, msg)
		if got == dnssecSecure {
			t.Fatalf("forged answer reported secure — a single valid signature against a non-anchored key is not a chain of trust (ING-09)")
		}
		if got != dnssecRRSIGOnly {
			t.Fatalf("validateDNSSEC = %q, want rrsig-only", got)
		}
	})

	t.Run("key only in response Extra is not trusted -> bogus", func(t *testing.T) {
		rrset, sig, key := signedA(t, "6.6.6.6")
		msg := new(dns.Msg)
		msg.Answer = append(append([]dns.RR{}, rrset...), sig)
		msg.Extra = append(msg.Extra, key) // the ONLY copy of the verifying key
		// Honest resolver has no such key (zone unsigned / different key). The
		// response-Extra key must be ignored, leaving nothing that verifies.
		c := &dnsCanary{fetchKeys: func(context.Context, string) ([]*dns.DNSKEY, error) {
			return nil, nil
		}}
		if got := validateDNSSEC(ctx, c, msg); got != dnssecBogus {
			t.Fatalf("validateDNSSEC = %q, want bogus — a key taken only from the Additional section must not be trusted (G7-10)", got)
		}
	})
}
