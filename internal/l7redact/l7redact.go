// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package l7redact holds the L7 data-minimization rules (D-43) that BOTH the
// eBPF agent and the control-plane ingest strip apply, so the two layers can
// never disagree about what an L7 call may persist.
//
// The agent applies Minimize to every parsed call before it is published to the
// bus; the control plane applies the same function again at ingest, before any
// consumer projects or persists the record, whatever the agent sent. One
// function, two call sites: a fix lands in both layers at once.
//
// The redaction modes, from strictest to loosest:
//
//	length   — no payload bytes cross the kernel boundary at all; no L7 calls.
//	metadata — only method, the templated route (no query string, identifier
//	           segments replaced by {id}), status, latency, byte counts,
//	           protocol and the 5-tuple persist. The default whenever L7
//	           capture is consented, on every deployment profile.
//	headers  — header names and non-sensitive header values survive in the
//	           agent's parse window; the route keeps its literal segments.
//	           An explicit, audited opt-in (tenant governance policy).
//	full     — consented debugging only; refused under the regulated profile.
package l7redact

import (
	"strings"
)

// Redaction modes. The strings are the agent's l7_capture_redaction values and
// the tenant governance policy's l7_capture_redaction values.
const (
	ModeLength   = "length"
	ModeMetadata = "metadata"
	ModeHeaders  = "headers"
	ModeFull     = "full"
)

// DefaultMode is the mode that applies when nothing stricter or looser has been
// stated explicitly: no tenant policy row, no floor received, no agent setting.
const DefaultMode = ModeMetadata

// Placeholder replaces an identifier-bearing route segment.
const Placeholder = "{id}"

// OtherMethod replaces a method that is not a recognized token (the OTel
// semantic-convention value for an unknown HTTP method).
const OtherMethod = "_OTHER"

// strictness ranks the modes; a higher rank persists less.
func strictness(mode string) int {
	switch mode {
	case ModeLength:
		return 3
	case ModeMetadata:
		return 2
	case ModeHeaders:
		return 1
	case ModeFull:
		return 0
	default:
		return -1
	}
}

// ValidMode reports whether mode is one of the four redaction modes.
func ValidMode(mode string) bool { return strictness(mode) >= 0 }

// Modes lists the modes from strictest to loosest.
func Modes() []string { return []string{ModeLength, ModeMetadata, ModeHeaders, ModeFull} }

// Normalize returns mode, or DefaultMode for an empty value. An unknown value is
// returned unchanged so the caller's validation can name it.
func Normalize(mode string) string {
	if mode == "" {
		return DefaultMode
	}
	return mode
}

// Looser reports whether mode persists more than floor allows. An unknown mode
// is always looser (fail closed); an unknown floor is treated as DefaultMode.
func Looser(mode, floor string) bool {
	f := strictness(Normalize(floor))
	if f < 0 {
		f = strictness(DefaultMode)
	}
	return strictness(Normalize(mode)) < f
}

// Stricter returns the stricter of a and b (empty and unknown values count as
// DefaultMode).
func Stricter(a, b string) string {
	a, b = known(a), known(b)
	if strictness(a) >= strictness(b) {
		return a
	}
	return b
}

func known(mode string) string {
	mode = Normalize(mode)
	if !ValidMode(mode) {
		return DefaultMode
	}
	return mode
}

// Persists reports whether mode lets any L7 call leave the agent or reach a
// store at all: under length, none does (D-43 S7).
func Persists(mode string) bool { return known(mode) != ModeLength }

// Minimizing reports whether mode applies the metadata persistence rule
// (templated route, normalized method, no statement text).
func Minimizing(mode string) bool { return strictness(known(mode)) >= strictness(ModeMetadata) }

// Protocol identifiers, mirrored from the eBPF L7 parsers (internal/ebpf/l7) so
// this package stays dependency-free for both of its callers.
const (
	protoHTTP1    = "http1"
	protoHTTP2    = "http2"
	protoGRPC     = "grpc"
	protoDNS      = "dns"
	protoKafka    = "kafka"
	protoPostgres = "postgresql"
	protoMySQL    = "mysql"
	// ProtoOther replaces an unrecognized protocol value under metadata.
	ProtoOther = "other"
)

// knownProtocols is the L7 protocol vocabulary (the eBPF parsers' ids).
var knownProtocols = map[string]bool{
	"": true, protoHTTP1: true, protoHTTP2: true, protoGRPC: true, protoDNS: true,
	protoKafka: true, protoPostgres: true, protoMySQL: true, ProtoOther: true,
}

// Protocol clamps an L7 protocol value to the vocabulary ("other" otherwise).
// It applies under every mode: a protocol is an enum, never free text.
func Protocol(p string) (string, Strip) {
	if knownProtocols[p] {
		return p, 0
	}
	return ProtoOther, StripEnum
}

// Enum clamps v to vocab ("other" otherwise; "" is always allowed).
func Enum(v string, vocab ...string) (string, Strip) {
	if v == "" {
		return v, 0
	}
	for _, w := range vocab {
		if v == w {
			return v, 0
		}
	}
	return ProtoOther, StripEnum
}

// maxLabelBytes bounds an identifier-valued field (a DNS name's limit).
const maxLabelBytes = 253

// InvalidLabel replaces an identifier-valued field that cannot be one.
const InvalidLabel = "_invalid"

// Label validates an identifier-valued field — a workload, process name,
// container id, host or address: at most 253 bytes of letters, digits, space
// and . _ : / @ + - ( ) [ ] # ~ , (kernel thread and process names use the
// brackets and parentheses). Anything else (quotes, braces, '?', '=', '&', control or
// non-ASCII bytes — the shape of a body, header or query) is not an identifier
// and is replaced by InvalidLabel. An identifier-shaped value cannot be
// content-checked: this bounds shape, not meaning.
func Label(v string) (string, Strip) {
	if len(v) > maxLabelBytes {
		return InvalidLabel, StripLabel
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !isAlnum(c) && !strings.ContainsRune(" ._:/@+-()[]#~,", rune(c)) {
			return InvalidLabel, StripLabel
		}
	}
	return v, 0
}

// Call is the protocol-neutral view of one L7 call's free-text fields: the only
// fields of an L7 call that can carry application data. Everything else on the
// wire record is numeric or an enum.
type Call struct {
	Protocol string
	Method   string
	Resource string
	Status   string
}

// Strip names one kind of removal, for the strip counters.
type Strip uint16

const (
	// StripQuery: a query string or fragment was cut from a route.
	StripQuery Strip = 1 << iota
	// StripIdentifier: an identifier-bearing route segment became {id}.
	StripIdentifier
	// StripMatrix: a ;matrix parameter (e.g. ;jsessionid=) was cut from a segment.
	StripMatrix
	// StripMethod: a method that is not a recognized token became _OTHER.
	StripMethod
	// StripStatement: SQL statement text was dropped.
	StripStatement
	// StripResource: a resource of an unrecognized protocol was dropped.
	StripResource
	// StripStatus: a status that is not a short token became _OTHER.
	StripStatus
	// StripProtocol: an unrecognized protocol value became "other".
	StripProtocol
	// StripTruncated: a route was cut to its length or segment bound.
	StripTruncated
	// StripEnum: an enum-valued field (a protocol, transport, direction)
	// carried a value outside its vocabulary.
	StripEnum
	// StripLabel: an identifier-valued field (a workload, process, host or
	// address) carried bytes no identifier has, or exceeded its bound.
	StripLabel
	// StripSubdomain: a DNS name was cut to its registered domain (D-65 (c)).
	StripSubdomain
)

// stripNames is the fixed label set the counters expose (never a value from the
// record itself).
var stripNames = []struct {
	bit  Strip
	name string
}{
	{StripQuery, "query"},
	{StripIdentifier, "identifier_segment"},
	{StripMatrix, "matrix_param"},
	{StripMethod, "method"},
	{StripStatement, "statement"},
	{StripResource, "resource"},
	{StripStatus, "status"},
	{StripProtocol, "protocol"},
	{StripTruncated, "truncated"},
	{StripEnum, "enum_field"},
	{StripLabel, "label_field"},
	{StripSubdomain, "dns_subdomain"},
}

// StripFields lists every strip label, in a fixed order.
func StripFields() []string {
	out := make([]string, 0, len(stripNames))
	for _, s := range stripNames {
		out = append(out, s.name)
	}
	return out
}

// Fields returns the labels of the strips in s, in StripFields order.
func (s Strip) Fields() []string {
	var out []string
	for _, n := range stripNames {
		if s&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// MinimizeWith applies mode's persistence rule to c and reports what it removed.
//
// Under every mode a query string or fragment never survives in an HTTP or gRPC
// route (ING-16). Under metadata (and length, which normally has no calls at
// all) the route is templated, the method and status are reduced to tokens, SQL
// statement text is dropped, an unrecognized protocol keeps no resource, and a
// DNS question name is templated left of its registered domain (D-65; the NDR
// detectors score on in-agent features, never on the stored name). Minimize is
// idempotent: Minimize(Minimize(c)) == Minimize(c).
// opt carries the deployment's choices (the regulated profile's
// registered-domain-only DNS names, D-65).
func MinimizeWith(c Call, mode string, opt Options) (Call, Strip) {
	var strip Strip
	minimize := Minimizing(mode)
	switch c.Protocol {
	case protoHTTP1, protoHTTP2:
		c.Resource, strip = route(c.Resource, minimize)
		if minimize {
			if m := httpMethod(c.Method); m != c.Method {
				c.Method, strip = m, strip|StripMethod
			}
		}
	case protoGRPC:
		c.Resource, strip = route(c.Resource, minimize)
		if minimize && c.Method != "" {
			m, ms := route("/"+strings.TrimPrefix(c.Method, "/"), true)
			if m = strings.TrimPrefix(m, "/"); m != c.Method {
				c.Method, strip = m, strip|ms
			}
		}
	case protoPostgres, protoMySQL:
		if minimize {
			if c.Resource != "" {
				c.Resource, strip = "", strip|StripStatement
			}
			if m := tokenOr(c.Method, 24); m != c.Method {
				c.Method, strip = m, strip|StripMethod
			}
		}
	case protoDNS:
		if minimize {
			// D-65: identifiers left of the registered domain never persist;
			// under the regulated profile only the registered domain does.
			if c.Resource != "" {
				r, rs := DNSName(c.Resource, opt.DNSRegisteredDomainOnly)
				c.Resource, strip = r, strip|rs
			}
			if m := tokenOr(c.Method, 16); m != c.Method {
				c.Method, strip = m, strip|StripMethod
			}
		}
	case protoKafka:
		if minimize {
			if c.Resource != "" {
				r, rs := templateName(c.Resource)
				c.Resource, strip = r, strip|rs
			}
			if m := tokenOr(c.Method, 32); m != c.Method {
				c.Method, strip = m, strip|StripMethod
			}
		}
	default:
		if minimize {
			if c.Protocol != "" && c.Protocol != ProtoOther {
				c.Protocol, strip = ProtoOther, strip|StripProtocol
			}
			if c.Resource != "" {
				c.Resource, strip = "", strip|StripResource
			}
			if c.Method != "" && c.Method != OtherMethod {
				c.Method, strip = OtherMethod, strip|StripMethod
			}
		}
	}
	if minimize {
		if s := statusFor(c.Protocol, c.Status); s != c.Status {
			c.Status, strip = s, strip|StripStatus
		}
	}
	return c, strip
}

// route strips the query string (always) and, when minimize is set, templates
// the path.
func route(path string, minimize bool) (string, Strip) {
	var strip Strip
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path, strip = path[:i], StripQuery
	}
	if !minimize {
		return path, strip
	}
	t, ts := TemplateRoute(path)
	return t, strip | ts
}

// httpMethods are the methods that survive verbatim under metadata.
var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true,
	"CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true,
}

func httpMethod(m string) string {
	if m == "" || httpMethods[m] {
		return m
	}
	return OtherMethod
}

// tokenOr returns s when it is a short token of letters, digits, space, '_' or
// '-', else OtherMethod.
func tokenOr(s string, limit int) string {
	if s == "" || s == OtherMethod {
		return s
	}
	if len(s) > limit {
		return OtherMethod
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != ' ' && c != '_' && c != '-' {
			return OtherMethod
		}
	}
	return s
}

// statusFor bounds a status under metadata: an HTTP status is three digits, a
// gRPC status one or two digits (review N6 — an HTTP/2 :status could carry
// "password authentication failed"); other protocols keep a short token.
func statusFor(protocol, status string) string {
	switch protocol {
	case protoHTTP1, protoHTTP2:
		return digitsOr(status, 3, 3)
	case protoGRPC:
		return digitsOr(status, 1, 2)
	}
	return statusToken(status)
}

func digitsOr(s string, minLen, maxLen int) string {
	if s == "" || s == OtherMethod {
		return s
	}
	if len(s) < minLen || len(s) > maxLen {
		return OtherMethod
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return OtherMethod
		}
	}
	return s
}

// statusToken bounds a status to a short token (HTTP code, grpc-status, DNS
// rcode, SQL command tag such as "INSERT 0 1").
func statusToken(s string) string { return tokenOr(s, 32) }
