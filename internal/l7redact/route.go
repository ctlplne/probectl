// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7redact

import "strings"

// Route bounds. A templated route is a low-cardinality fault-finding key, not a
// transcript of the request target: past these bounds the rest is cut.
const (
	maxRouteSegments = 32
	maxRouteBytes    = 512
	// truncatedMarker ends a route that was cut at a bound.
	truncatedMarker = "{truncated}"
)

// TemplateRoute is the shared route-templating function (D-43 refinement 1):
// it cuts the query string and fragment, cuts ;matrix parameters, and replaces
// every identifier-bearing path segment with {id}. Numeric, UUID, hex, long
// token-like and mixed identifier segments (a contract number such as
// W56HZV-23-C-0123, a patient number, a session token) all collapse; word
// segments, API versions (v1, v2beta1) and short protocol names (oauth2, ec2)
// survive, so /contracts/W56HZV-23-C-0123/drawings becomes
// /contracts/{id}/drawings and /patients/48213 becomes /patients/{id}.
//
// What it cannot see: an identifier that is shaped like a word (a username such
// as /users/alice). Routes of that shape need the application to template them
// itself; the metadata mode documents the limit (docs/ebpf-agent.md).
//
// It returns the templated route and the strips it made.
func TemplateRoute(path string) (string, Strip) {
	var strip Strip
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path, strip = path[:i], StripQuery
	}
	if path == "" {
		return "", strip
	}
	segs := strings.Split(path, "/")
	if len(segs) > maxRouteSegments+1 { // +1: the empty segment before a leading '/'
		segs, strip = append(segs[:maxRouteSegments+1:maxRouteSegments+1], truncatedMarker), strip|StripTruncated
	}
	for i, seg := range segs {
		if seg == "" || seg == truncatedMarker {
			continue
		}
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			seg, strip = seg[:j], strip|StripMatrix
		}
		t, ts := templateSegment(seg)
		segs[i], strip = t, strip|ts
	}
	out := strings.Join(segs, "/")
	if len(out) > maxRouteBytes {
		cut := strings.LastIndexByte(out[:maxRouteBytes-len(truncatedMarker)-1], '/')
		if cut < 0 {
			cut = 0
		}
		out, strip = out[:cut]+"/"+truncatedMarker, strip|StripTruncated
	}
	return out, strip
}

// templateName templates a dotted name (a Kafka topic) label by label.
func templateName(name string) (string, Strip) {
	if len(name) > maxRouteBytes {
		return Placeholder, StripIdentifier | StripTruncated
	}
	return templateSegment(name)
}

// templateSegment templates one path segment. A segment is split into labels on
// '.' and ':' (grpc.health.v1.Health, index.html, items:batchGet); each label
// becomes {id} when it, or any of its '-' / '_' parts, is an identifier token.
// Adjacent {id} labels collapse, so 10.0.0.1 is one {id}, not four.
func templateSegment(seg string) (string, Strip) {
	if seg == Placeholder || seg == truncatedMarker {
		return seg, 0
	}
	if isUUID(seg) || !plainSegment(seg) {
		// Encoded or structured content (%40, @, =, +, ~, non-ASCII ...) cannot
		// be judged label by label: the whole segment is an identifier.
		return Placeholder, StripIdentifier
	}
	var (
		b      strings.Builder
		strip  Strip
		prevID bool
		sep    byte = '.'
		start  int
	)
	b.Grow(len(seg))
	for i := 0; i <= len(seg); i++ {
		if i < len(seg) && seg[i] != '.' && seg[i] != ':' {
			continue
		}
		label := seg[start:i]
		id := label == Placeholder || labelIsIdentifier(label)
		if id && label != Placeholder {
			strip |= StripIdentifier
		}
		// Adjacent {id} labels collapse into one, separator included.
		if !id || !prevID {
			if start > 0 {
				b.WriteByte(sep)
			}
			if id {
				b.WriteString(Placeholder)
			} else {
				b.WriteString(label)
			}
		}
		prevID = id
		if i < len(seg) {
			sep = seg[i]
		}
		start = i + 1
	}
	return b.String(), strip
}

// plainSegment reports whether seg holds only letters, digits and the label
// separators templateSegment understands.
func plainSegment(seg string) bool {
	seg = strings.ReplaceAll(seg, Placeholder, "x") // an already-templated label is plain
	for i := 0; i < len(seg); i++ {
		if c := seg[i]; !isAlnum(c) && c != '.' && c != ':' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// labelIsIdentifier reports whether a dot/colon label is identifier-bearing: the
// whole label, or any of its '-' / '_' separated parts, is an identifier token.
func labelIsIdentifier(label string) bool {
	if label == "" {
		return false
	}
	if hasTokenPrefix(label) {
		return true
	}
	start := 0
	for i := 0; i <= len(label); i++ {
		if i == len(label) || label[i] == '-' || label[i] == '_' {
			if tokenIsIdentifier(label[start:i]) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// tokenIsIdentifier classifies one separator-free token.
func tokenIsIdentifier(t string) bool {
	if t == "" {
		return false
	}
	var digits, letters, lower int
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			letters++
		case c >= 'a' && c <= 'z':
			letters++
			lower++
		default:
			// Any other byte (%, @, =, +, ~, non-ASCII ...) means encoded or
			// structured content this function cannot judge: never keep it.
			return true
		}
	}
	if len(t) >= 32 {
		return true // long token-like (session ids, digests, JWT parts)
	}
	if digits > 0 {
		if digits == len(t) {
			return true // numeric id
		}
		if isVersion(t) || keptMixedWords[asciiLowerString(t)] {
			return false // v1, v2beta1; oauth2, ec2, k8s
		}
		// Any other mix of letters and digits is an identifier: user123,
		// acct42, ABCD123, a1b2c3 (D-43 refinement 1, review S6).
		return true
	}
	// No digits: a word, unless it reads as an encoding of something.
	if len(t) >= 12 && isHexString(t) {
		return true // digit-free hex: deadbeefcafebabe
	}
	if len(t) >= 6 && caseTransitions(t)*2 >= len(t) {
		return true // base64-ish case churn: MzEyMw, AbCdEfGhIjKlMnOp
	}
	if len(t) >= 12 && longestConsonantRun(t) >= 6 {
		return true
	}
	if len(t) >= 16 && lower > 0 && hasAdjacentUpper(t) {
		return true
	}
	return false
}

// keptMixedWords are the letter-and-digit tokens that name a protocol,
// product or standard rather than a record; every other mixed token is an
// identifier.
var keptMixedWords = map[string]bool{
	"oauth2": true, "ec2": true, "s3": true, "k8s": true, "http2": true, "h2c": true,
	"md5": true, "sha1": true, "sha256": true, "sha512": true, "x509": true,
	"base64": true, "utf8": true, "ipv4": true, "ipv6": true, "2fa": true,
	"i18n": true, "l10n": true, "e2e": true, "p2p": true, "b2b": true,
	"mp3": true, "mp4": true, "h264": true, "3ds": true,
}

// tokenPrefixes are credential families a route segment can carry whole.
var tokenPrefixes = []string{
	"sk-", "sk_", "pk_", "rk_", "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_",
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "glpat-", "AKIA", "ASIA", "AIza", "ya29", "eyJ",
}

// hasTokenPrefix reports whether label starts like a known credential family
// (the prefix alone is never a route word).
func hasTokenPrefix(label string) bool {
	for _, p := range tokenPrefixes {
		if len(label) > len(p) && strings.HasPrefix(label, p) {
			return true
		}
	}
	return false
}

func isHexString(t string) bool {
	for i := 0; i < len(t); i++ {
		if !isHex(t[i]) {
			return false
		}
	}
	return true
}

// caseTransitions counts adjacent letter pairs whose case differs.
func caseTransitions(t string) int {
	n := 0
	for i := 1; i < len(t); i++ {
		a, b := t[i-1], t[i]
		if isLetter(a) && isLetter(b) && isUpper(a) != isUpper(b) {
			n++
		}
	}
	return n
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func asciiLowerString(t string) string {
	b := []byte(t)
	for i := range b {
		b[i] = asciiLower(b[i])
	}
	return string(b)
}

// isVersion matches v<digits> with an optional lowercase suffix and digits:
// v1, v12, v2beta1, v1alpha.
func isVersion(t string) bool {
	if len(t) < 2 || (t[0] != 'v' && t[0] != 'V') {
		return false
	}
	i := 1
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i == 1 || i > 4 {
		return false
	}
	for i < len(t) && t[i] >= 'a' && t[i] <= 'z' {
		i++
	}
	j := i
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	return i == len(t) && i-j <= 3
}

func longestConsonantRun(t string) int {
	best, run := 0, 0
	for i := 0; i < len(t); i++ {
		switch asciiLower(t[i]) {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			run = 0
		default:
			run++
			if run > best {
				best = run
			}
		}
	}
	return best
}

func hasAdjacentUpper(t string) bool {
	for i := 1; i < len(t); i++ {
		if isUpper(t[i-1]) && isUpper(t[i]) {
			return true
		}
	}
	return false
}

// isUUID matches the canonical 8-4-4-4-12 hex form.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func asciiLower(c byte) byte {
	if isUpper(c) {
		return c + ('a' - 'A')
	}
	return c
}
