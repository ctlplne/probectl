// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otel

import (
	"strconv"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// SemConvVersion pins the OpenTelemetry semantic-convention version whose
// attribute names probectl's mapping follows (SCHEMA-004). It is emitted as the
// OTLP Resource/ScopeMetrics SchemaUrl and as the InstrumentationScope Version,
// so a downstream collector can machine-detect which convention version the
// hand-mapped keys (server.address, network.transport, ...) conform to. When we
// adopt a newer semconv revision (renames/unit changes), bump this single
// constant and re-verify the mapping — the conformance test fails if the emitted
// SchemaUrl drifts from it.
const (
	SemConvVersion = "1.27.0"
	// SchemaURL is the canonical OTel schema URL for SemConvVersion. The OTLP
	// spec carries the convention version as this URL, never a bare version.
	SchemaURL = "https://opentelemetry.io/schemas/" + SemConvVersion
	// ScopeName / ScopeVersion identify probectl as the instrumentation scope.
	// ScopeVersion is the probectl build's mapping version (tracks SemConvVersion).
	ScopeName    = "probectl"
	ScopeVersion = SemConvVersion
)

// OTel resource + network semantic-convention attribute keys probectl emits. The
// names follow the OpenTelemetry specification; probectl-specific identity uses the
// probectl.* namespace, since OTel has no standard tenancy attribute.
const (
	AttrTenantID         = "probectl.tenant.id"
	AttrAgentID          = "probectl.agent.id"
	AttrCanaryType       = "probectl.canary.type"
	AttrServerAddress    = "server.address"
	AttrServerPort       = "server.port"
	AttrNetworkTransport = "network.transport"
	AttrNetworkProtocol  = "network.protocol.name"
)

// KnownAttributes is the set of attribute keys the core mapping may emit — OTel
// standard names plus the probectl.* namespace. The conformance test asserts
// ResultAttributes never emits a key outside this set, i.e. probectl does not
// invent an attribute name where an OTel convention already exists.
//
// OTel semconv 1.27.0 standard keys are used where a standard exists; keys
// with no OTel equivalent live under the probectl.* namespace (ARCH-001).
var KnownAttributes = map[string]bool{
	// Core identity (probectl namespace — no OTel standard for tenancy).
	AttrTenantID:   true,
	AttrAgentID:    true,
	AttrCanaryType: true,
	// OTel network semantic conventions (semconv 1.27.0).
	AttrServerAddress:    true,
	AttrServerPort:       true,
	AttrNetworkTransport: true,
	AttrNetworkProtocol:  true,
	// OTel network peer (semconv 1.27.0) — emitted by HTTP + ICMP canaries.
	"network.peer.address":     true,
	"network.peer.port":        true,
	"network.protocol.version": true,
	// OTel HTTP semantic conventions (semconv 1.27.0) — emitted by HTTP canary.
	"http.response.status_code": true,
	// OTel TLS semantic conventions (semconv 1.27.0) — emitted by HTTP canary.
	"tls.protocol.version": true,
	"tls.cipher.suite":     true, // was "tls.cipher" — renamed to OTel standard (ARCH-001)
	// probectl.* namespace: ICMP canary specifics (no OTel standard).
	"probectl.icmp.mode":                 true,
	"probectl.icmp.dropped_seqs":         true,
	"probectl.icmp.drop_send_offsets_ms": true,
	// probectl.* namespace: DNS canary specifics (no OTel standard).
	"probectl.dns.rcode":     true,
	"probectl.dns.answer":    true,
	"probectl.dns.dnssec":    true,
	"probectl.dns.trace":     true,
	"probectl.dns.qtype":     true,
	"probectl.dns.transport": true,
	"probectl.dns.mode":      true,
	"probectl.dns.server":    true,
	// probectl.* namespace: TLS detail keys (no OTel standard).
	"probectl.tls.resumed":               true,
	"probectl.tls.verification_disabled": true,
	"probectl.tls.server.verified":       true,
	"probectl.tls.server.subject":        true,
	"probectl.tls.server.issuer":         true,
	"probectl.tls.server.not_before":     true,
	"probectl.tls.server.not_after":      true,
	"probectl.tls.server.san":            true,
	"probectl.tls.server.chain":          true,
	"probectl.tls.server.cert":           true,
	// probectl.* namespace: voice/RTP canary specifics (no OTel standard).
	"probectl.voice.jitter_buffer_ms": true,
}

// ResultAttributes maps a Result to its OTel resource + network attributes — the
// canonical mapping the TSDB labels (S6) and the OTLP layer (S22) build on. The
// result's own attributes map is passed through; canaries populate it with
// OTel-convention keys.
func ResultAttributes(r *resultv1.Result) map[string]string {
	attrs := map[string]string{
		AttrTenantID:   r.GetTenantId(),
		AttrAgentID:    r.GetAgentId(),
		AttrCanaryType: r.GetCanaryType(),
	}
	if v := r.GetServerAddress(); v != "" {
		attrs[AttrServerAddress] = v
	}
	if v := r.GetServerPort(); v != 0 {
		attrs[AttrServerPort] = strconv.FormatUint(uint64(v), 10)
	}
	if v := r.GetNetworkTransport(); v != "" {
		attrs[AttrNetworkTransport] = v
	}
	if v := r.GetNetworkProtocolName(); v != "" {
		attrs[AttrNetworkProtocol] = v
	}
	for k, v := range r.GetAttributes() {
		attrs[k] = v
	}
	return attrs
}
