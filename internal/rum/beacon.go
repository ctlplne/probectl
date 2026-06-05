// Package rum is real-user monitoring convergence (S47b, F20): a privacy-first
// browser-beacon schema, server-side enforcement of that privacy contract, and
// the synthetic↔RUM correlation that completes DEM — "synthetics are red AND
// real users are hurting" vs "synthetics are red but no user impact observed"
// vs the blind-spot finding "users are hurting and synthetics never noticed".
//
// The privacy contract is STRUCTURAL and server-enforced (the S47b watch-out;
// the S37 endpoint-privacy precedent): a beacon without explicit consent is
// rejected; URLs are redacted (query/fragment stripped, volatile path segments
// collapsed) even if the SDK already redacted them; unknown fields are
// rejected outright so identifier-bearing payloads can never ingest; the
// client IP and user agent are never stored — the schema has no place to put
// them. Beacons normalize into the canonical result schema (S6 — one signal
// model, no parallel pipeline) and ride their own bus topic.
package rum

import (
	"encoding/json"
	"fmt"
	"strings"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// SchemaVersion is the beacon wire-schema version (the S47b contract).
const SchemaVersion = 1

// MaxBeaconBytes caps one beacon payload (guardrail 12 — untrusted input).
const MaxBeaconBytes = 16 << 10

// Beacon is the wire schema the browser SDK posts. Strictly decoded: unknown
// fields REJECT the beacon (privacy fail-closed — a payload carrying extra
// identifiers never ingests). Key rides the body because sendBeacon cannot
// set headers; it is an app identifier (public in page source, like every
// RUM product's site key), NOT a secret — it scopes and rate-limits, it
// grants no read access. It is stripped before storage.
type Beacon struct {
	V       int    `json:"v"`
	Key     string `json:"key"`     // app key → (tenant, app); never stored
	Consent bool   `json:"consent"` // explicit user consent; false/absent = rejected
	App     string `json:"app,omitempty"`
	Host    string `json:"host"` // the page host — the synthetic↔RUM join key
	Page    string `json:"page"` // path only; server re-redacts regardless
	Browser string `json:"browser,omitempty"`
	Vitals  Vitals `json:"vitals"`
	Errors  int    `json:"errors"`          // JS errors during the view
	Failed  int    `json:"failed_requests"` // failed fetch/XHR during the view
	SDK     string `json:"sdk,omitempty"`   // SDK version string
	_       struct{}
}

// PeekKey leniently extracts ONLY the app key from a payload — used to
// attribute rejections to the right tenant even when the strict parse will
// refuse the beacon. Returns "" when no key is recoverable.
func PeekKey(raw []byte) string {
	var probe struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return sanitizeLabel(probe.Key, 128)
}

// Vitals are the web-vitals measurements (milliseconds unless noted).
type Vitals struct {
	TTFBms float64 `json:"ttfb_ms,omitempty"`
	FCPms  float64 `json:"fcp_ms,omitempty"`
	LCPms  float64 `json:"lcp_ms,omitempty"`
	CLS    float64 `json:"cls,omitempty"` // unitless score
	INPms  float64 `json:"inp_ms,omitempty"`
	Loadms float64 `json:"load_ms,omitempty"`
}

// RejectReason classifies why a beacon was refused (served as honesty
// counters — the operator sees what is being dropped and why).
type RejectReason string

const (
	RejectMalformed RejectReason = "malformed"
	RejectNoConsent RejectReason = "no_consent"
	RejectBadField  RejectReason = "invalid_field"
)

// ParseBeacon strictly decodes and validates one beacon payload. The privacy
// gate is here: no consent → rejected; unknown fields → rejected; URL
// redaction is applied server-side regardless of what the SDK sent.
func ParseBeacon(raw []byte) (Beacon, RejectReason, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var b Beacon
	if err := dec.Decode(&b); err != nil {
		return Beacon{}, RejectMalformed, fmt.Errorf("rum: malformed beacon: %w", err)
	}
	if !b.Consent {
		return Beacon{}, RejectNoConsent, fmt.Errorf("rum: beacon without consent rejected (privacy contract)")
	}
	if b.V != SchemaVersion {
		return Beacon{}, RejectBadField, fmt.Errorf("rum: unsupported schema version %d", b.V)
	}
	host, ok := normalizeHost(b.Host)
	if !ok {
		return Beacon{}, RejectBadField, fmt.Errorf("rum: invalid host")
	}
	b.Host = host
	b.Page = RedactPath(b.Page)
	b.Browser = browserFamily(b.Browser)
	b.App = sanitizeLabel(b.App, 64)
	b.SDK = sanitizeLabel(b.SDK, 32)
	if !validVitals(b.Vitals) || b.Errors < 0 || b.Errors > 10000 || b.Failed < 0 || b.Failed > 10000 {
		return Beacon{}, RejectBadField, fmt.Errorf("rum: vitals out of bounds")
	}
	return b, "", nil
}

// normalizeHost lowercases and rejects hosts carrying ports, paths, userinfo
// or spaces (the join key must be a bare host).
func normalizeHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || len(h) > 253 || strings.ContainsAny(h, ":/@ \t?#") {
		return "", false
	}
	return h, true
}

// RedactPath strips query strings + fragments (token/PII carriers), bounds
// length, and collapses volatile segments (numbers, UUIDs, long hex/opaque
// IDs) to ":id" — privacy AND bounded page-group cardinality in one pass.
func RedactPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" || !strings.HasPrefix(p, "/") {
		p = "/" + strings.TrimPrefix(p, "/")
	}
	if len(p) > 256 {
		p = p[:256]
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if volatileSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

// volatileSegment reports whether a path segment looks like an identifier
// (numeric, UUID-ish, or long opaque token) rather than a route word.
func volatileSegment(s string) bool {
	if s == "" {
		return false
	}
	digits, hexish := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			hexish++
		case (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-':
			hexish++
		}
	}
	if digits == len(s) { // pure number
		return true
	}
	if len(s) >= 16 && hexish == len(s) { // uuid / hex token
		return true
	}
	if len(s) > 32 && digits > 0 { // long opaque id
		return true
	}
	return false
}

// browserFamily maps the SDK-reported browser onto a small allowlist —
// family-level only, never a full user-agent (fingerprinting surface).
func browserFamily(b string) string {
	switch strings.ToLower(strings.TrimSpace(b)) {
	case "chrome", "chromium":
		return "chrome"
	case "firefox":
		return "firefox"
	case "safari":
		return "safari"
	case "edge":
		return "edge"
	case "":
		return "unknown"
	default:
		return "other"
	}
}

// sanitizeLabel bounds a free-text label and strips control characters.
func sanitizeLabel(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	var sb strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func validVitals(v Vitals) bool {
	for _, ms := range []float64{v.TTFBms, v.FCPms, v.LCPms, v.INPms, v.Loadms} {
		if ms < 0 || ms > 600_000 { // 10 minutes — beyond that it is garbage
			return false
		}
	}
	return v.CLS >= 0 && v.CLS <= 100
}

// ToResult normalizes a validated beacon into the canonical result schema
// (S6): tenant comes from the VERIFIED app key — never the payload; the
// timestamp is the server's receive time — client clocks are untrusted.
// Attribute names follow OTel semconv where one exists (url.path, browser.*).
func ToResult(tenant, app string, b Beacon, receivedUnixNano int64) *resultv1.Result {
	if app == "" {
		app = b.App
	}
	if app == "" {
		app = "(unattributed)"
	}
	metrics := map[string]float64{
		"rum.errors":          float64(b.Errors),
		"rum.failed_requests": float64(b.Failed),
	}
	addVital := func(name string, v float64) {
		if v > 0 {
			metrics[name] = v
		}
	}
	addVital("rum.ttfb_ms", b.Vitals.TTFBms)
	addVital("rum.fcp_ms", b.Vitals.FCPms)
	addVital("rum.lcp_ms", b.Vitals.LCPms)
	addVital("rum.inp_ms", b.Vitals.INPms)
	addVital("rum.load_ms", b.Vitals.Loadms)
	if b.Vitals.CLS > 0 {
		metrics["rum.cls"] = b.Vitals.CLS
	}
	return &resultv1.Result{
		TenantId:          tenant,
		CanaryType:        "rum",
		ServerAddress:     b.Host,
		Success:           b.Errors == 0 && b.Failed == 0,
		StartTimeUnixNano: receivedUnixNano,
		Metrics:           metrics,
		Attributes: map[string]string{
			"rum.app":      app,
			"url.path":     b.Page,
			"browser.name": b.Browser,
			"rum.sdk":      b.SDK,
		},
	}
}
