// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
)

// verifyRRSIG is the pure DNSSEC check: given an answer RRset, the RRSIGs over
// it, and candidate DNSKEYs, it returns "secure" (a valid, in-window signature
// from a matching key), "insecure" (no RRSIG — the zone is unsigned), or "bogus"
// (RRSIGs present but none verify: tampered, expired, or wrong key). This
// validates the zone's signature on the answer — it does NOT trust the AD bit
// (CLAUDE.md / sprint watch-out). Full chain-to-root validation is a refinement.
func verifyRRSIG(rrset []dns.RR, rrsigs []*dns.RRSIG, keys []*dns.DNSKEY) string {
	if len(rrsigs) == 0 {
		return dnssecInsecure
	}
	if len(keys) == 0 {
		return dnssecBogus
	}
	now := time.Now()
	for _, sig := range rrsigs {
		covered := coveredRRs(rrset, sig.TypeCovered)
		if len(covered) == 0 {
			continue
		}
		for _, k := range keys {
			if sig.KeyTag != k.KeyTag() {
				continue
			}
			if sig.ValidityPeriod(now) && sig.Verify(k, covered) == nil {
				return dnssecSecure
			}
		}
	}
	return dnssecBogus
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

// validateDNSSEC validates the answer's signatures, fetching the signer zone's
// DNSKEYs when they are not already present in the response.
func validateDNSSEC(ctx context.Context, c *dnsCanary, msg *dns.Msg) string {
	rrset, rrsigs := splitAnswer(msg)
	if len(rrsigs) == 0 {
		return dnssecInsecure
	}
	keys := dnskeysIn(msg)
	if len(keys) == 0 {
		fetched, err := c.fetchDNSKEYs(ctx, rrsigs[0].SignerName)
		if err != nil {
			return dnssecBogus
		}
		keys = fetched
	}
	return verifyRRSIG(rrset, rrsigs, keys)
}

func dnskeysIn(msg *dns.Msg) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Extra...) {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

// fetchDNSKEYs queries the signer zone for its DNSKEY RRset.
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
