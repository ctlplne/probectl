package ebpf

import (
	"bytes"
	"fmt"
)

// TLS-plaintext capture policy (U-003, C13; path map in
// docs/audit/ebpf-capture-redaction.md). Live sslsniff capture is
// PII-class — it reads application plaintext on customer hosts — so it is:
//
//  1. OFF by default: l7_capture_enabled must be set true;
//  2. consent-gated per tenant: l7_capture_consent_tenant must equal the
//     agent's bound tenant exactly (the agent is tenant-bound at
//     registration, so consent is an explicit per-tenant statement in the
//     deployment config — absent or mismatched, capture stays off);
//  3. redacted at the user-space boundary: between the ring-buffer read and
//     ANY retention/parsing, payload bodies are zeroed in place and only
//     protocol metadata survives (configurable; "full" requires the same
//     consent gate and exists for consented debugging).
//
// The FixtureL7Source (recorded replay for CI/demos) is not live capture
// and is exempt. The L4 flow plane (no payloads) is unaffected.

// Redaction modes for the capture boundary.
const (
	// RedactHeaders (the default) keeps protocol metadata: for HTTP-framed
	// chunks everything through the header terminator survives and the body
	// is zeroed in place; for non-HTTP chunks only the protocol-detection
	// window (first redactKeepPrefix bytes) survives.
	RedactHeaders = "headers"
	// RedactFull disables payload redaction (consented debugging only —
	// still behind the same enable+consent gate).
	RedactFull = "full"
)

// redactKeepPrefix is the survival window for non-HTTP-framed chunks: enough
// for protocol detection and early metadata (HTTP/2 preface is 24 bytes; DNS
// and Kafka carry their identifiers early), nowhere near a request body.
const redactKeepPrefix = 128

var (
	headerTerminator = []byte("\r\n\r\n")
	// http2Preface contains an EARLY header terminator; keep the whole
	// 24-byte preface so protocol detection still routes the stream (the
	// HPACK frames after it are zeroed — http2/grpc call extraction under
	// "headers" redaction is a documented limitation).
	http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
)

// l7CaptureAuthorized is the consent gate: both the explicit enable AND the
// per-tenant consent (matching the agent's bound tenant) are required.
func l7CaptureAuthorized(cfg *Config) (bool, string) {
	if !cfg.L7CaptureEnabled {
		return false, "TLS-plaintext capture is OFF by default (set l7_capture_enabled + per-tenant consent; U-003)"
	}
	if cfg.L7CaptureConsentTenant == "" {
		return false, "l7_capture_enabled without l7_capture_consent_tenant — consent must name the tenant explicitly (U-003)"
	}
	if cfg.L7CaptureConsentTenant != cfg.TenantID {
		return false, fmt.Sprintf("l7_capture_consent_tenant %q does not match this agent's tenant %q — capture stays off (U-003)",
			cfg.L7CaptureConsentTenant, cfg.TenantID)
	}
	return true, ""
}

// RedactPayload applies the capture-boundary policy IN PLACE on p (the
// caller's private copy) and returns it. Length is preserved so protocol
// framing (e.g. Content-Length accounting) stays parseable; the zeroed
// region is the retained-plaintext kill zone.
func RedactPayload(p []byte, mode string) []byte {
	if mode == RedactFull {
		return p
	}
	keep := redactKeepPrefix
	if i := bytes.Index(p, headerTerminator); i >= 0 {
		keep = i + len(headerTerminator) // headers (metadata) survive; the body is zeroed
	}
	if bytes.HasPrefix(p, http2Preface) && keep < len(http2Preface) {
		keep = len(http2Preface)
	}
	if keep >= len(p) {
		return p
	}
	z := p[keep:]
	for i := range z {
		z[i] = 0
	}
	return p
}

// validRedactionMode reports whether mode is a known capture-boundary policy.
func validRedactionMode(mode string) bool {
	return mode == RedactHeaders || mode == RedactFull
}
