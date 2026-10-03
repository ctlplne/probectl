// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dnssecSecure   = "secure"
	dnssecInsecure = "insecure"
	dnssecBogus    = "bogus"
	// dnssecIndeterminate: the answer's RRSIGs cryptographically verify against the
	// signer zone's own DNSKEY RRset, but that keyset does NOT chain to a configured
	// trust anchor through a DS chain of trust. It is an HONEST signal — NOT
	// "secure" — because an unanchored signature proves only that *some* key signed
	// the answer, not that it is the zone's legitimate key: a forged answer signed
	// by an attacker's self-made key (and a malicious resolver serving that key)
	// verifies identically. We never claim "secure" without an anchored chain. This
	// is the RFC 4035 "Indeterminate" security state. docs/guardrails.md G7-9
	// (detection is an honest, accurate signal), G7-10 (fetched content is
	// untrusted).
	dnssecIndeterminate = "indeterminate"
)

// verifyRRSIG is the pure DNSSEC signature check: given an answer RRset, the
// RRSIGs over it, and candidate DNSKEYs, it returns "secure" (EVERY answer RRset
// carries a valid, in-window signature from a matching key), "insecure" (no
// RRSIG — the zone is unsigned), or "bogus" (RRSIGs present but some answer
// RRset does not verify: tampered, expired, or wrong key). It validates the
// zone's signatures on the answer — it does NOT trust the AD bit (never the AD
// bit). It is deliberately NOT an authenticity verdict on its own: the keys it
// is handed are unanchored, so callers (validateDNSSEC) only promote a "secure"
// crypto result to the "secure" verdict once the keyset chains to a trust anchor.
func verifyRRSIG(rrset []dns.RR, rrsigs []*dns.RRSIG, keys []*dns.DNSKEY) string {
	if len(rrsigs) == 0 {
		return dnssecInsecure
	}
	if len(keys) == 0 {
		return dnssecBogus
	}
	types := answerTypes(rrset)
	if len(types) == 0 {
		return dnssecBogus
	}
	now := time.Now()
	// EVERY answer RRset must verify — a single valid RRSIG over one RRset no
	// longer vouches for the rest of the answer (docs/guardrails.md G7-9).
	for _, qtype := range types {
		if !rrsetVerifies(rrset, rrsigs, keys, qtype, now) {
			return dnssecBogus
		}
	}
	return dnssecSecure
}

// rrsetVerifies reports whether the RRset of a single type carries a valid,
// in-window RRSIG signed by one of the supplied keys.
func rrsetVerifies(rrset []dns.RR, rrsigs []*dns.RRSIG, keys []*dns.DNSKEY, qtype uint16, now time.Time) bool {
	covered := coveredRRs(rrset, qtype)
	if len(covered) == 0 {
		return false
	}
	for _, sig := range rrsigs {
		if sig.TypeCovered != qtype {
			continue
		}
		for _, k := range keys {
			if sig.KeyTag != k.KeyTag() {
				continue
			}
			if sig.ValidityPeriod(now) && sig.Verify(k, covered) == nil {
				return true
			}
		}
	}
	return false
}

// answerTypes lists the distinct RR types present in an answer RRset, preserving
// first-seen order.
func answerTypes(rrset []dns.RR) []uint16 {
	seen := make(map[uint16]bool)
	var out []uint16
	for _, rr := range rrset {
		t := rr.Header().Rrtype
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func coveredRRs(rrset []dns.RR, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrset {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}

// splitAnswer separates the answer RRset from its RRSIGs.
func splitAnswer(msg *dns.Msg) (rrset []dns.RR, rrsigs []*dns.RRSIG) {
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		} else {
			rrset = append(rrset, rr)
		}
	}
	return rrset, rrsigs
}

// validateDNSSEC validates the answer's signatures and returns the honest DNSSEC
// status. It NEVER trusts DNSKEYs carried in the response's own Answer/Extra
// sections — fetched/response content is untrusted (docs/guardrails.md G7-10),
// and an attacker who forges an answer would simply ship a self-made key beside
// it — so keys come only from a separate DNSKEY query to the signer zone. A
// cryptographically valid signature over those self-published keys is reported
// "secure" ONLY when the keyset chains to a configured trust anchor (the baked
// IANA root anchor, or an operator-pinned DS); otherwise authenticity is
// indeterminate (docs/guardrails.md G7-9). See anchoredKeyset.
func validateDNSSEC(ctx context.Context, c *dnsCanary, msg *dns.Msg) string {
	rrset, rrsigs := splitAnswer(msg)
	if len(rrsigs) == 0 {
		return dnssecInsecure
	}
	fetch := c.fetchKeys
	if fetch == nil {
		fetch = c.fetchDNSKEYs
	}
	keyMsg, err := fetch(ctx, rrsigs[0].SignerName)
	if err != nil || keyMsg == nil {
		return dnssecBogus
	}
	keys, keySigs := dnskeyRRset(keyMsg)
	switch verifyRRSIG(rrset, rrsigs, keys) {
	case dnssecInsecure:
		return dnssecInsecure
	case dnssecSecure:
		// The answer verifies against the zone's self-published DNSKEY RRset.
		// Promote to "secure" ONLY when that keyset chains to a configured trust
		// anchor; without an anchored chain the signature is unanchored and
		// authenticity is indeterminate (G7-9/G7-10).
		if anchoredKeyset(c.anchors(), keys, keySigs, time.Now()) {
			return dnssecSecure
		}
		return dnssecIndeterminate
	default:
		return dnssecBogus
	}
}

// dnskeyRRset extracts the DNSKEY records and the RRSIG(s) covering the DNSKEY
// RRset (the zone's self-signature over its own keyset) from a DNSKEY response.
func dnskeyRRset(msg *dns.Msg) (keys []*dns.DNSKEY, sigs []*dns.RRSIG) {
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

// anchoredKeyset reports whether the zone's DNSKEY RRset chains to one of the
// trust anchors. Two things must hold (RFC 4035 §5): a key in the set is pinned
// directly by an anchor DS (the parent-DS -> child-DNSKEY link), AND the DNSKEY
// RRset is self-signed by that anchored key — which vouches for every
// zone-signing key in the set, and therefore for the answer the caller already
// verified against the set. Without BOTH, the signature is unanchored and must
// NOT be reported "secure" (docs/guardrails.md G7-9, G7-10).
//
// Requiring the self-signature closes the obvious forgery: an attacker who
// serves a legitimate, anchored KSK alongside their own key cannot produce an
// RRSIG from the anchored key that covers the injected key — the signature can
// only ever cover the exact keyset the real zone signed.
func anchoredKeyset(anchors []*dns.DS, keys []*dns.DNSKEY, keySigs []*dns.RRSIG, now time.Time) bool {
	anchored := anchoredKeys(anchors, keys)
	if len(anchored) == 0 {
		return false
	}
	keyRRs := dnskeysAsRR(keys)
	for _, sig := range keySigs {
		if sig.TypeCovered != dns.TypeDNSKEY || !sig.ValidityPeriod(now) {
			continue
		}
		for _, ak := range anchored {
			if sig.KeyTag == ak.KeyTag() && sig.Verify(ak, keyRRs) == nil {
				return true
			}
		}
	}
	return false
}

// anchoredKeys returns the DNSKEYs whose DS digest matches one of the trust
// anchors (same key tag, algorithm, digest type and digest). The digest is
// recomputed from the key with the anchor's digest type via miekg/dns — the
// hash never leaves that library (docs/guardrails.md G7-3).
func anchoredKeys(anchors []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, k := range keys {
		if k == nil {
			continue
		}
		for _, a := range anchors {
			if a == nil {
				continue
			}
			ds := k.ToDS(a.DigestType)
			if ds == nil {
				continue
			}
			if ds.KeyTag == a.KeyTag && ds.Algorithm == a.Algorithm && strings.EqualFold(ds.Digest, a.Digest) {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func dnskeysAsRR(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, 0, len(keys))
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

// anchors returns the trust anchors this canary chains to: the operator-pinned
// set when configured (trust_anchor), otherwise the baked IANA root anchors.
func (c *dnsCanary) anchors() []*dns.DS {
	if len(c.trustAnchors) > 0 {
		return c.trustAnchors
	}
	return rootTrustAnchors()
}

// rootTrustAnchors returns the IANA DNS root zone trust anchors — the root KSK
// DS records published at data.iana.org/root-anchors/root-anchors.xml — baked
// in as the default chain-of-trust entry point. They are compiled-in constants,
// evaluated with no network access (docs/guardrails.md G7-2, no phone-home); an
// operator overrides them per canary with a pinned DS (the trust_anchor param),
// e.g. for a sovereign or air-gapped internal root.
func rootTrustAnchors() []*dns.DS {
	return []*dns.DS{
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     20326,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
		},
		{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     38696,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
		},
	}
}

// fetchDNSKEYs queries the signer zone for its DNSKEY RRset over the configured
// resolver and returns the response. The keys it carries are the zone's
// self-published keys — they are NOT trusted until anchoredKeyset chains them to
// a trust anchor, so a signature that verifies against them is never on its own
// treated as "secure" (docs/guardrails.md G7-10).
func (c *dnsCanary) fetchDNSKEYs(ctx context.Context, zone string) (*dns.Msg, error) {
	msg, _, err := c.query(ctx, c.server, dns.Fqdn(zone), dns.TypeDNSKEY, true)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
