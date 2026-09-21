// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package redactpat is the ONE place probectl defines what a secret, an
// identifier or a piece of PII LOOKS LIKE (Foundation-Loop S-e5e1b903).
//
// Two independent redaction engines used to carry parallel regex sets for the
// same shapes — bearer tokens, credential key-values, email, IP, MAC — with
// different coverage and no shared primitive. That is the classic
// duplicated-security-control failure: a masking fix lands in one engine and
// the other keeps leaking. The AI egress path (internal/ai) and the
// governance/support path (internal/govern) now compile the same patterns from
// here.
//
// This package owns RECOGNITION only. What to do with a match — mask, hash,
// drop, tokenize per tenant — stays with each consumer, because those
// strategies genuinely differ: the AI path emits reversible-per-tenant tokens
// so a model can reason about "the same host", while governance pseudonymizes
// for export. Sharing the patterns and NOT the strategies is the split that
// keeps both honest.
package redactpat

import (
	"net/netip"
	"regexp"
	"strings"
)

// Secret shapes. These are ALWAYS masked by every consumer, on every path,
// regardless of policy: there is no configuration under which a bearer token
// or a private key should cross a boundary.
var (
	// Bearer matches an Authorization header value or a bare bearer token.
	// The govern engine previously split this into two patterns and the AI
	// engine into one; the union is what both now use. Group 1 is the
	// scheme/header prefix, so a consumer that wants to keep the prefix
	// visible can replace with "${1}"+placeholder, and one that wants the
	// whole match gone can ignore the group.
	Bearer = regexp.MustCompile(`(?i)\b((?:bearer|authorization:)\s+)[A-Za-z0-9._~+/=-]{8,}`)

	// CredentialKV matches key=value / key: value credentials. The value class
	// excludes quotes and ampersands so redacting a JSON-rendered payload or a
	// query string never eats a structural character and corrupts the
	// document — a property the AI engine had and the govern engine encoded
	// separately; both now inherit it.
	CredentialKV = regexp.MustCompile(`(?i)\b((?:api[_\-.]?key|access[_\-.]?key|secret|token|password|passwd|pwd)\s*[=:]\s*)[^\s"'&]+`)

	// AWSAccessKeyID matches an AKIA-prefixed access key id.
	AWSAccessKeyID = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// PEMBlock matches a whole PEM-armored block (private keys, certificates).
	PEMBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)
)

// Identifier and PII shapes. Whether these are masked is POLICY — each
// consumer decides — but what they look like is not.
var (
	// Email must be applied BEFORE any hostname pass, so the domain part is
	// consumed as part of the address rather than masked separately.
	Email = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	// MAC matches colon- or dash-separated hardware addresses.
	MAC = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)

	// IPv4 optionally carries a CIDR suffix so a prefix is masked whole.
	IPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

	// IPv6Candidate is deliberately loose: consumers VALIDATE each candidate
	// with netip.ParseAddr, so clock times ("12:30") and C++ scope operators
	// never survive as matches. A tight regex here would be both unreadable
	// and wrong.
	IPv6Candidate = regexp.MustCompile(`(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:%[0-9a-zA-Z]+)?(?:/\d{1,3})?|::[fF]{4}:(?:\d{1,3}\.){3}\d{1,3}`)

	// Hostname matches dotted DNS names. Applied after Email.
	Hostname = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b`)

	// URL matches an absolute http(s) URL, which may embed credentials, hosts
	// and identifiers all at once.
	URL = regexp.MustCompile(`https?://[^\s"'<>()]+`)
)

// SecretShape is one always-masked pattern plus the one thing a consumer needs
// to know to apply it: whether the pattern captures a prefix worth leaving
// visible. `api_key=` and `Authorization: Bearer ` are diagnostic — an operator
// reading a support bundle needs to see WHICH credential was present — while
// the value after it is not.
type SecretShape struct {
	// Name is stable and is what tests and audit trails refer to.
	Name string
	// Pattern matches the whole secret, including any prefix.
	Pattern *regexp.Regexp
	// KeepPrefix means Pattern's group 1 is a prefix to preserve.
	KeepPrefix bool
}

// Secrets is the always-masked set, in application order: whole PEM blocks
// first (they contain everything else), then header/bearer values, then
// key-value credentials, then bare key ids.
//
// Consumers ITERATE this rather than naming patterns themselves. That is what
// makes the sharing structural instead of cosmetic: a new secret shape appended
// here is masked on every path at once, and cannot be added to one engine and
// forgotten in the other, because neither engine has its own list to forget.
func Secrets() []SecretShape {
	return []SecretShape{
		{Name: "pem_block", Pattern: PEMBlock},
		{Name: "bearer", Pattern: Bearer, KeepPrefix: true},
		{Name: "credential_kv", Pattern: CredentialKV, KeepPrefix: true},
		{Name: "aws_access_key_id", Pattern: AWSAccessKeyID},
	}
}

// MaskSecrets applies every shape in Secrets with the caller's placeholder
// strategy. placeholder receives the matched secret and returns what replaces
// it; any preserved prefix is re-attached by this function, so a consumer
// cannot get the prefix handling right for one shape and wrong for another.
func MaskSecrets(s string, placeholder func(shape SecretShape, match string) string) string {
	for _, shape := range Secrets() {
		s = shape.Pattern.ReplaceAllStringFunc(s, func(m string) string {
			out := placeholder(shape, m)
			if shape.KeepPrefix {
				if g := shape.Pattern.FindStringSubmatch(m); len(g) > 1 {
					return g[1] + out
				}
			}
			return out
		})
	}
	return s
}

// TrimIPSuffix strips a CIDR prefix length from an IPv4/IPv6 candidate so the
// address itself can be validated. A zone (`%eth0`) is left in place —
// netip.ParseAddr understands zones, and the zone is itself identifying.
func TrimIPSuffix(candidate string) string {
	s := strings.TrimSpace(candidate)
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// IsIPv4 reports whether a candidate match is a real IPv4 address, tolerating a
// CIDR suffix.
func IsIPv4(candidate string) bool {
	addr, err := netip.ParseAddr(TrimIPSuffix(candidate))
	return err == nil && addr.Is4()
}

// IsIPv6 reports whether a candidate match is a real IPv6 address, tolerating a
// CIDR suffix and a zone. This is what stops IPv6Candidate's deliberate
// looseness from masking clock times and C++ scope operators: recognition is
// regex PLUS parse, and both consumers get the same answer.
func IsIPv6(candidate string) bool {
	addr, err := netip.ParseAddr(TrimIPSuffix(candidate))
	return err == nil && !addr.Is4()
}

// MaskIPv4 scans s for IPv4 addresses (optionally CIDR-suffixed) and replaces
// each with mask(match). Like MaskIPv6 it pairs the pattern with a parse, so
// "999.999.999.999" and a build tag like "1.2.3.4000" are not addresses on
// either path — the two engines used to disagree about exactly this.
func MaskIPv4(s string, mask func(match string) string) string {
	return IPv4.ReplaceAllStringFunc(s, func(m string) string {
		if !IsIPv4(m) {
			return m
		}
		return mask(m)
	})
}

// MaskIPv6 scans s for IPv6 addresses and replaces each with mask(match).
//
// Both consumers go through here rather than driving IPv6Candidate themselves,
// because recognizing an IPv6 address takes three steps and getting only two of
// them right is how `std::vector::iterator` used to come out of BOTH engines as
// a masked address: the regex matches `d::`, and netip.ParseAddr agrees that
// `d::` is the valid address 000d:: — the miss is that it is not a STANDALONE
// token. The third step is the boundary check below, and it lives here so
// neither consumer can forget it.
func MaskIPv6(s string, mask func(match string) string) string {
	spans := IPv6Candidate.FindAllStringIndex(s, -1)
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, span := range spans {
		start, end := span[0], span[1]
		if !standaloneIPv6(s, start, end) {
			continue
		}
		b.WriteString(s[prev:start])
		b.WriteString(mask(s[start:end]))
		prev = end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// standaloneIPv6 reports whether the span is a real address rather than a
// fragment of a larger identifier. An address is preceded and followed by
// something that is not an identifier character: `fe80::1` in prose qualifies,
// the `d::` inside `std::vector` does not.
func standaloneIPv6(s string, start, end int) bool {
	if start > 0 && isIdentByte(s[start-1]) {
		return false
	}
	if end < len(s) && isIdentByte(s[end]) {
		return false
	}
	return IsIPv6(s[start:end])
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '-' ||
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z')
}
