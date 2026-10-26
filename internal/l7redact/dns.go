// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7redact

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Options carries deployment-wide minimization choices both layers apply.
type Options struct {
	// DNSRegisteredDomainOnly keeps only the registered domain (eTLD+1) of a
	// DNS question name — the regulated profile (D-65 (c)).
	DNSRegisteredDomainOnly bool
}

// maxDNSName is a DNS name's length bound.
const maxDNSName = 253

// DNSName minimizes a DNS question name (D-65): the labels left of the
// registered domain are templated with the same identifier rules as route
// segments (48213.patients.example.com becomes {id}.patients.example.com), or,
// with registeredOnly, only the registered domain survives (example.com). The
// registered domain comes from the ICANN section of the public-suffix list
// compiled into golang.org/x/net/publicsuffix — offline, nothing fetched. The
// PRIVATE section is deliberately not used (D-65 R1): there a cloud provider's
// customer label is "registered" (bucket-48213.s3.amazonaws.com), so the
// registered domain is the ICANN one (amazonaws.com) and the customer label is
// judged like any other. In a TLD the ICANN list does not know (.internal,
// .corp, .local, .lan) the second-level label is judged too. A name with no
// registered domain (a single label) has every label judged.
//
// An identifier-shaped label that IS the ICANN registered label (48213.com) is
// kept by default and templated with registeredOnly ({id}.com, decision D-68).
// What it cannot see, as for routes: a word-shaped identifier label
// (alice.users.corp.internal keeps "alice").
func DNSName(name string, registeredOnly bool) (string, Strip) {
	var strip Strip
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", 0
	}
	if len(name) > maxDNSName {
		name, strip = name[len(name)-maxDNSName:], StripTruncated
		if i := strings.IndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
	}
	if !plainDNSName(name) || hasEmptyLabel(name) {
		// Non-DNS bytes or an empty label: not a name this function can judge.
		return Placeholder, strip | StripIdentifier
	}
	domain, listed := registeredDomainOf(name)
	left := ""
	if domain != "" && len(name) > len(domain) {
		left = name[:len(name)-len(domain)-1]
	} else if domain == "" {
		left = name
	}
	if domain != "" && (!listed || registeredOnly) {
		// D-65 R1: a TLD the ICANN list does not know (.internal, .corp,
		// .local, .lan) gives no organization boundary — its second-level
		// label is judged like any other (w56hzv-23-c-0123.internal). D-68:
		// under the regulated profile an identifier-shaped ICANN registered
		// label is judged too (48213.com becomes {id}.com).
		if sld, tld, _ := strings.Cut(domain, "."); sld == Placeholder || labelIsIdentifier(sld) {
			if sld != Placeholder {
				strip |= StripIdentifier
			}
			domain = Placeholder + "." + tld
		}
	}
	if left == "" {
		return boundDNSName(domain, strip)
	}
	if registeredOnly && domain != "" {
		return boundDNSName(domain, strip|StripSubdomain)
	}
	var out []string
	prevID := false
	for _, label := range strings.Split(left, ".") {
		id := label == Placeholder || labelIsIdentifier(label)
		if id && label != Placeholder {
			strip |= StripIdentifier
		}
		if id && prevID {
			continue
		}
		if id {
			label = Placeholder
		}
		out = append(out, label)
		prevID = id
	}
	if domain != "" {
		if prevID && strings.HasPrefix(domain, Placeholder+".") {
			out = out[:len(out)-1] // {id}.{id}.internal collapses like route labels
		}
		out = append(out, domain)
	}
	return boundDNSName(strings.Join(out, "."), strip)
}

// boundDNSName keeps a templated name within maxDNSName. {id} is longer than
// a one- to three-byte label, so templating can grow a name that fit: every
// return path goes through here (DPR-405; the registered-domain-only paths
// once skipped it and came out one byte over). Leading labels are dropped
// first, so the registered domain, which is last, survives. When dropping
// would leave a single label, the result is {id} instead: a lone label would be
// judged again on a second pass ("000…" becomes {id}), and the output must be
// stable under DNSName.
func boundDNSName(res string, strip Strip) (string, Strip) {
	for len(res) > maxDNSName {
		i := strings.IndexByte(res, '.')
		if i < 0 || !strings.Contains(res[i+1:], ".") {
			return Placeholder, strip | StripTruncated
		}
		res, strip = res[i+1:], strip|StripTruncated
	}
	return res, strip
}

func hasEmptyLabel(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..")
}

// plainDNSName reports whether name holds only DNS-name bytes (letters,
// digits, '-', '_', '.') or already-templated labels.
func plainDNSName(name string) bool {
	name = strings.ReplaceAll(name, Placeholder, "x")
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isAlnum(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// RegisteredDomain returns the registered domain of name by the ICANN rules
// (the last two labels in a TLD the list does not know), or "" when it has
// none. The eBPF agent keys the tunneling detector's subdomain token on it.
func RegisteredDomain(name string) string {
	d, _ := registeredDomainOf(strings.TrimSuffix(name, "."))
	return d
}

// registeredDomainOf finds the registered domain of name: one label left of
// its longest ICANN public suffix (listed=true), else — a TLD the ICANN list
// does not know — the last two labels (listed=false), else "". Labels keep
// their case; the lookup is case-insensitive.
func registeredDomainOf(name string) (string, bool) {
	labels := strings.Split(name, ".")
	lower := strings.Split(strings.ToLower(name), ".")
	for i := 1; i < len(labels); i++ {
		cand := strings.Join(lower[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(cand); icann && ps == cand {
			return strings.Join(labels[i-1:], "."), true
		}
	}
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], "."), false
	}
	return "", false
}
