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
var KnownAttributes = map[string]bool{
	AttrTenantID:         true,
	AttrAgentID:          true,
	AttrCanaryType:       true,
	AttrServerAddress:    true,
	AttrServerPort:       true,
	AttrNetworkTransport: true,
	AttrNetworkProtocol:  true,
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
