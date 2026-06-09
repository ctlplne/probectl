// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"fmt"
)

// TLS-plaintext capture policy (U-003, C13; path map in
// the agent security whitepaper). Live sslsniff capture is
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
	// RedactLengthOnly captures NO payload bytes: the kernel window is 0, so
	// only chunk metadata (direction, true size, connection key) transits the
	// ring — traffic shape without any plaintext. Parsed L7 calls are
	// unavailable in this mode (there is nothing to parse), by design.
	RedactLengthOnly = "length"
	// RedactFull disables payload redaction (consented debugging only —
	// still behind the same enable+consent+scope gates).
	RedactFull = "full"
)

// Kernel capture-window bounds (EBPF-002): the window is how many plaintext
// bytes per chunk may transit the kernel ring AT ALL — body bytes past it
// never leave kernel space. The BPF map is zero-initialized (window 0 =
// length-only), so an unprogrammed policy fails closed.
const (
	// defaultKernelWindow covers a request line + typical headers + every
	// protocol-detection signature under "headers" redaction.
	defaultKernelWindow = 1024
	// minKernelWindow keeps protocol detection viable (HTTP/2 preface is 24
	// bytes; DNS/Kafka identifiers sit early; redactKeepPrefix is 128).
	minKernelWindow = 128
	// maxKernelWindow is MAX_DATA-1 in bpf/sslsniff.bpf.c.
	maxKernelWindow = 4095
)

// kernelWindowFor maps the consented redaction mode to the kernel capture
// window programmed into capture_cfg.
func kernelWindowFor(mode string, configured int) uint32 {
	switch mode {
	case RedactLengthOnly:
		return 0
	case RedactFull:
		return maxKernelWindow
	default: // RedactHeaders
		if configured == 0 {
			return defaultKernelWindow
		}
		return uint32(configured)
	}
}

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

// l7CaptureAuthorized is the consent gate — now THREE explicit statements
// (U-003 + EBPF-001): the enable flag, the per-tenant consent (matching the
// agent's bound tenant), and a non-empty process-scope allowlist naming the
// opted-in workloads. Host-wide capture is not expressible.
func l7CaptureAuthorized(cfg *Config) (bool, string) {
	if !cfg.L7CaptureEnabled {
		return false, "TLS-plaintext capture is OFF by default (set l7_capture_enabled + per-tenant consent + l7_capture_scope; U-003)"
	}
	if cfg.L7CaptureConsentTenant == "" {
		return false, "l7_capture_enabled without l7_capture_consent_tenant — consent must name the tenant explicitly (U-003)"
	}
	if cfg.L7CaptureConsentTenant != cfg.TenantID {
		return false, fmt.Sprintf("l7_capture_consent_tenant %q does not match this agent's tenant %q — capture stays off (U-003)",
			cfg.L7CaptureConsentTenant, cfg.TenantID)
	}
	if len(cfg.L7CaptureScope) == 0 {
		return false, "l7_capture_enabled without l7_capture_scope — capture must name the opted-in workloads (pid:/exe:/cgroup:), never the whole host (EBPF-001)"
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
	if mode == RedactLengthOnly {
		// The kernel window is 0 in this mode, so p is normally already
		// empty — this is defense in depth for any other caller.
		for i := range p {
			p[i] = 0
		}
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
	return mode == RedactHeaders || mode == RedactLengthOnly || mode == RedactFull
}
