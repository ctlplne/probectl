// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"crypto"
	"encoding/base64"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// miekg/dns rejects a zero RRSIG key tag even when generated key material is
// valid. Resample only that unsupported fixture value, before signing; never
// retry a signature or a validation failure.
func dnssecSigningKey(key *dns.DNSKEY, generate func(int) (crypto.PrivateKey, error)) (crypto.Signer, error) {
	for range 8 {
		private, err := generate(256)
		if err != nil {
			return nil, err
		}
		if key.KeyTag() == 0 {
			continue
		}
		signer, ok := private.(crypto.Signer)
		if !ok {
			return nil, errors.New("generated DNSSEC key is not a signer")
		}
		return signer, nil
	}
	return nil, errors.New("DNSSEC fixture generated eight unsupported zero key tags")
}

func testDNSSECSigningKey(t *testing.T, key *dns.DNSKEY) crypto.Signer {
	t.Helper()
	signer, err := dnssecSigningKey(key, key.Generate)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestDNSSECSigningFixtureRejectsZeroTagBeforeRealSignature(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	// Synthetic public bytes force the checksum edge deterministically. They
	// are never used for a signature: the next attempt generates a real key.
	zeroTag := make([]byte, 64)
	copy(zeroTag, []byte{0xff, 0xff, 0xfb, 0xf2})
	key.PublicKey = base64.StdEncoding.EncodeToString(zeroTag)
	if key.KeyTag() != 0 {
		t.Fatal("zero-tag counterexample no longer reaches the library edge")
	}
	zeroPublic := key.PublicKey
	calls := 0
	signer, err := dnssecSigningKey(key, func(bits int) (crypto.PrivateKey, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return key.Generate(bits)
	})
	if err != nil || signer == nil || calls < 2 || key.KeyTag() == 0 {
		t.Fatal("zero-tag fixture was accepted or real regeneration failed", calls, err)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}
	sig := &dns.RRSIG{Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name}
	if err := sig.Sign(signer, []dns.RR{a}); err != nil {
		t.Fatal("regenerated real key cannot sign", err)
	}
	if err := sig.Verify(key, []dns.RR{a}); err != nil {
		t.Fatal("regenerated real signature does not verify", err)
	}
	a.A = net.ParseIP("192.0.2.8")
	if err := sig.Verify(key, []dns.RR{a}); err == nil {
		t.Fatal("modified answer retained a valid signature")
	}
	key.PublicKey = zeroPublic
	calls = 0
	if signer, err := dnssecSigningKey(key, func(int) (crypto.PrivateKey, error) {
		calls++
		return nil, nil
	}); err == nil || signer != nil || calls != 8 {
		t.Fatal("unsupported fixture retries are unbounded or fail open", calls, err)
	}
}
