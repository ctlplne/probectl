package otel

import ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"

// L7 call attribute keys (S21), following the OpenTelemetry http.* / rpc.* /
// dns.* / messaging.* semantic conventions. Identity (tenant/agent) and the edge
// endpoints reuse the keys in conventions.go / flow.go.
const (
	AttrHTTPRequestMethod      = "http.request.method"
	AttrHTTPResponseStatusCode = "http.response.status_code"
	AttrURLPath                = "url.path"
	AttrRPCSystem              = "rpc.system"
	AttrRPCMethod              = "rpc.method"
	AttrRPCGRPCStatusCode      = "rpc.grpc.status_code"
	AttrDNSQuestionName        = "dns.question.name"
	AttrDNSResponseCode        = "dns.response.code"
	AttrMessagingSystem        = "messaging.system"
	AttrMessagingOperation     = "messaging.operation.name"
	AttrMessagingDestination   = "messaging.destination.name"
	AttrL7Encrypted            = "probectl.l7.encrypted"
)

func init() {
	for _, k := range []string{
		AttrHTTPRequestMethod, AttrHTTPResponseStatusCode, AttrURLPath,
		AttrRPCSystem, AttrRPCMethod, AttrRPCGRPCStatusCode,
		AttrDNSQuestionName, AttrDNSResponseCode,
		AttrMessagingSystem, AttrMessagingOperation, AttrMessagingDestination,
		AttrL7Encrypted,
	} {
		KnownAttributes[k] = true
	}
}

// L7CallAttributes maps an eBPF L7Call to its OTel attributes, by protocol — the
// mapping the OTLP layer (S22) exposes as spans/metrics rather than remapping.
func L7CallAttributes(c *ebpfv1.L7Call) map[string]string {
	attrs := map[string]string{
		AttrTenantID:        c.GetTenantId(),
		AttrAgentID:         c.GetAgentId(),
		AttrNetworkProtocol: c.GetProtocol(),
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	if c.GetEncrypted() {
		attrs[AttrL7Encrypted] = "true"
	}
	switch c.GetProtocol() {
	case "http1", "http2":
		put(AttrHTTPRequestMethod, c.GetMethod())
		put(AttrURLPath, c.GetResource())
		put(AttrHTTPResponseStatusCode, c.GetStatus())
	case "grpc":
		attrs[AttrRPCSystem] = "grpc"
		put(AttrRPCMethod, c.GetMethod())
		put(AttrRPCGRPCStatusCode, c.GetStatus())
	case "dns":
		put(AttrDNSQuestionName, c.GetResource())
		put(AttrDNSResponseCode, c.GetStatus())
	case "kafka":
		attrs[AttrMessagingSystem] = "kafka"
		put(AttrMessagingOperation, c.GetMethod())
		put(AttrMessagingDestination, c.GetResource())
	}
	return attrs
}
