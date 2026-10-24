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
// registered domain comes from the public-suffix list compiled into
// golang.org/x/net/publicsuffix — offline, nothing fetched. A name with no
// registered domain (a bare suffix, a single label) has every label judged.
//
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
	if !plainDNSName(name) {
		return Placeholder, strip | StripIdentifier
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(name))
	if err != nil {
		domain = ""
	}
	left := name
	if domain != "" {
		if len(name) == len(domain) {
			return name, strip
		}
		left = name[:len(name)-len(domain)-1]
	}
	if registeredOnly && domain != "" {
		return domain, strip | StripSubdomain
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
		out = append(out, domain)
	}
	return strings.Join(out, "."), strip
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

// RegisteredDomain returns the registered domain (eTLD+1) of name, or "" when
// it has none. The NDR detectors key tunneling on it.
func RegisteredDomain(name string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(name, ".")))
	if err != nil {
		return ""
	}
	return d
}
