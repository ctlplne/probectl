// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Network identities must match complete addresses, never address or zone
// prefixes. Other directory aliases retain their existing literal-text policy.
func literalSubjectPattern(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !isSafeContainsIdentifier(value) {
		return "", false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return networkSubjectPattern(address), true
	}
	return "(?i)" + regexp.QuoteMeta(value), true
}

func networkSubjectPattern(address netip.Addr) string {
	// A non-hex protocol prefix (snmp:, ipfix:, ...) cannot be an IPv6
	// hextet. This accepts source-reference wrappers without accepting a
	// suffix of a different valid IPv6 address.
	left := `(^|[^[:alnum:]_.:%+-])(?:[a-fA-F0-9+.-]*[g-zG-Z][[:alnum:]+.-]*:)?`
	var variants []string
	zone := address.Zone()
	if address.Is4() || (address.Is4In6() && zone == "") {
		v4 := address.Unmap()
		variants = append(variants, left+regexp.QuoteMeta(v4.String())+networkSubjectEnd(false))
		for _, body := range ipv6SubjectBodies(netip.AddrFrom16(v4.As16())) {
			variants = append(variants, left+body+networkSubjectEnd(true))
		}
	}
	if address.Is6() {
		for _, body := range ipv6SubjectBodies(address) {
			right := networkSubjectEnd(true)
			if zone != "" {
				// Interface zones are case-sensitive. Keep their complete
				// spelling rather than folding them with the IPv6 hex digits.
				body += "%" + regexp.QuoteMeta(zone)
				// Closing brackets are not an unconditional zone delimiter:
				// en1]suffix is a different zone. Accept a bracket only as
				// part of a complete bracketed address/endpoint wrapper.
				right = `($|[[:space:]/{}(),;"'<>])`
				variants = append(variants, left+`\[`+body+`\](?::[0-9]+)?`+right)
			}
			variants = append(variants, left+body+right)
		}
	}
	sort.Strings(variants)
	unique := variants[:0]
	for _, variant := range variants {
		if len(unique) == 0 || unique[len(unique)-1] != variant {
			unique = append(unique, variant)
		}
	}
	return "(?:" + strings.Join(unique, "|") + ")"
}

func networkSubjectEnd(ipv6 bool) string {
	identifier := `[:alnum:]_.%+-`
	if ipv6 {
		identifier = `[:alnum:]_.:%+-`
	}
	// A sentence's final period is punctuation; a dot followed by a host
	// label/number is part of a different address or hostname.
	return `($|[^` + identifier + `]|[.]($|[^` + identifier + `]))`
}

// Every equivalent IPv6 spelling: independent hextet leading zeroes, all
// legal zero-compression positions, and the IPv4 dotted-tail representation.
// Comparing only String/StringExpanded would miss other valid spellings.
func ipv6SubjectBodies(address netip.Addr) []string {
	bytes := address.As16()
	parts := make([]string, 8)
	zero := make([]bool, 8)
	for i := range parts {
		word := uint16(bytes[2*i])<<8 | uint16(bytes[2*i+1])
		zero[i] = word == 0
		literal := fmt.Sprintf("%x", word)
		if word == 0 {
			parts[i] = "0{1,4}"
		} else {
			parts[i] = fmt.Sprintf("0{0,%d}", 4-len(literal)) + foldAddressHex(literal)
		}
	}
	forms := func(words []string, zero []bool) []string {
		out := []string{strings.Join(words, ":")}
		for first := range zero {
			for last := first; last < len(zero) && zero[last]; last++ {
				out = append(out, strings.Join(words[:first], ":")+"::"+strings.Join(words[last+1:], ":"))
			}
		}
		return out
	}
	out := forms(parts, zero)
	tail := netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
	dotted := append(append([]string{}, parts[:6]...), regexp.QuoteMeta(tail.String()))
	return append(out, forms(dotted, zero[:6])...)
}

func foldAddressHex(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'f':
			out.WriteRune('[')
			out.WriteRune(r)
			out.WriteRune(r - 'a' + 'A')
			out.WriteRune(']')
		case r >= 'A' && r <= 'F':
			out.WriteRune('[')
			out.WriteRune(r - 'A' + 'a')
			out.WriteRune(r)
			out.WriteRune(']')
		default:
			out.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return out.String()
}
