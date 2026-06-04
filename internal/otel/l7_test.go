package otel

import (
	"testing"

	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
)

func TestL7CallAttributesConformToConventions(t *testing.T) {
	calls := []*ebpfv1.L7Call{
		{Protocol: "http1", Method: "GET", Resource: "/x", Status: "200", TenantId: "t", AgentId: "a"},
		{Protocol: "http2", Method: "POST", Resource: "/y", Status: "503", TenantId: "t", AgentId: "a"},
		{Protocol: "grpc", Method: "pkg.Svc/M", Status: "0", TenantId: "t", AgentId: "a", Encrypted: true},
		{Protocol: "dns", Method: "A", Resource: "x.com.", Status: "NOERROR", TenantId: "t", AgentId: "a"},
		{Protocol: "kafka", Method: "Fetch", TenantId: "t", AgentId: "a"},
	}
	for _, c := range calls {
		attrs := L7CallAttributes(c)
		for k := range attrs {
			if !KnownAttributes[k] {
				t.Errorf("protocol %s: attribute %q is not an OTel/probectl convention name", c.GetProtocol(), k)
			}
		}
	}
}

func TestL7CallAttributesHTTPAndGRPC(t *testing.T) {
	http := L7CallAttributes(&ebpfv1.L7Call{Protocol: "http1", Method: "GET", Resource: "/orders/42", Status: "200"})
	if http[AttrHTTPRequestMethod] != "GET" || http[AttrURLPath] != "/orders/42" || http[AttrHTTPResponseStatusCode] != "200" {
		t.Errorf("http attrs = %v", http)
	}
	grpc := L7CallAttributes(&ebpfv1.L7Call{Protocol: "grpc", Method: "pkg.Svc/M", Status: "13", Encrypted: true})
	if grpc[AttrRPCSystem] != "grpc" || grpc[AttrRPCMethod] != "pkg.Svc/M" || grpc[AttrRPCGRPCStatusCode] != "13" || grpc[AttrL7Encrypted] != "true" {
		t.Errorf("grpc attrs = %v", grpc)
	}
}
