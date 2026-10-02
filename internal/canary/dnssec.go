// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

const (
	dnssecSecure   = "secure"
	dnssecInsecure = "insecure"
	dnssecBogus    = "bogus"
	// dnssecRRSIGOnly: the answer's RRSIGs verify against the signer zone's own
	// DNSKEY, but that DNSKEY has NOT been anchored to the root through a DS
	// chain of trust. It is an HONEST signal — NOT "secure" — because an
	// unanchored signature proves only that *some* key signed the answer, not
	// that it is the zone's legitimate key: a forged answer signed by an
	// attacker's self-made key (and a malicious resolver serving that key) would
	// verify identically. We never claim "secure" without an anchored chain.
	// docs/guardrails.md G7-9 (detection is an honest signal), G7-10 (fetched
	// content is untrusted).
	dnssecRRSIGOnly = "rrsig-only"
)

// verifyRRSIG is the pure DNSSEC signature check: given an answer RRset, the
// RRSIGs over it, and candidate DNSKEYs, it returns "secure" (EVERY answer RRset
// carries a valid, in-window signature from a matching key), "insecure" (no
// RRSIG — the zone is unsigned), or "bogus" (RRSIGs present but some answer
// RRset does not verify: tampered, expired, or wrong key). It validates the
// zone's signatures on the answer — it does NOT trust the AD bit (never the AD
// bit). It is deliberately NOT an authenticity verdict on its own: the keys it
// is handed are unanchored, so callers (validateDNSSEC) downgrade a "secure"
// crypto result to rrsig-only until a DS chain to the root anchor is validated.
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
// it — so keys come only from a separate DNSKEY query to the signer zone. Even
// those keys are the zone's self-published keys, NOT anchored to the root via a
// DS chain of trust; a cryptographically valid signature over them is therefore
// reported as rrsig-only, never "secure" (docs/guardrails.md G7-9). Full
// root-anchored DS/DNSKEY chain validation is the follow-up that promotes
// rrsig-only to secure (see docs/configuration.md).
func validateDNSSEC(ctx context.Context, c *dnsCanary, msg *dns.Msg) string {
	rrset, rrsigs := splitAnswer(msg)
	if len(rrsigs) == 0 {
		return dnssecInsecure
	}
	fetch := c.fetchKeys
	if fetch == nil {
		fetch = c.fetchDNSKEYs
	}
	keys, err := fetch(ctx, rrsigs[0].SignerName)
	if err != nil {
		return dnssecBogus
	}
	switch verifyRRSIG(rrset, rrsigs, keys) {
	case dnssecInsecure:
		return dnssecInsecure
	case dnssecSecure:
		// Signatures verify against the zone's self-published DNSKEY, but that
		// key is not anchored to the root. We cannot honestly claim "secure"
		// (G7-9/G7-10) — report rrsig-only.
		return dnssecRRSIGOnly
	default:
		return dnssecBogus
	}
}

// fetchDNSKEYs queries the signer zone for its DNSKEY RRset over the configured
// resolver. The returned keys are the zone's self-published keys — they are NOT
// anchored to the root trust anchor, so callers must not treat a signature that
// verifies against them as "secure".
func (c *dnsCanary) fetchDNSKEYs(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	msg, _, err := c.query(ctx, c.server, dns.Fqdn(zone), dns.TypeDNSKEY, true)
	if err != nil {
		return nil, err
	}
	var keys []*dns.DNSKEY
	for _, rr := range msg.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
