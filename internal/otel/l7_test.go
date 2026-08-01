// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otel

import (
	"testing"

	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
)

func TestL7CallAttributesConformToConventions(t *testing.T) {
	calls := []*ebpfv1.L7Call{
		{Protocol: "http1", Method: "GET", Resource: "/x", Status: "200", TenantId: "t", AgentId: "a"},
		{Protocol: "http2", Method: "POST", Resource: "/y", Status: "503", TenantId: "t", AgentId: "a"},
		{Protocol: "grpc", Method: "pkg.Svc/M", Status: "0", TenantId: "t", AgentId: "a", Encrypted: true},
		{Protocol: "dns", Method: "A", Resource: "x.com.", Status: "NOERROR", TenantId: "t", AgentId: "a"},
		{Protocol: "kafka", Method: "Fetch", TenantId: "t", AgentId: "a"},
		{Protocol: "postgresql", Method: "SELECT", Resource: "SELECT * FROM users WHERE id = ?", Status: "SELECT 1", TenantId: "t", AgentId: "a"},
		{Protocol: "mysql", Method: "INSERT", Resource: "insert into orders values (?, ?)", Status: "OK", TenantId: "t", AgentId: "a"},
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

func TestL7CallAttributesSQL(t *testing.T) {
	sql := L7CallAttributes(&ebpfv1.L7Call{Protocol: "postgresql", Method: "SELECT", Resource: "SELECT * FROM users WHERE id = ?", Status: "SELECT 1"})
	if sql[AttrDBSystemName] != "postgresql" || sql[AttrDBOperationName] != "SELECT" || sql[AttrDBQueryText] != "SELECT * FROM users WHERE id = ?" || sql[AttrDBResponseStatusCode] != "SELECT 1" {
		t.Errorf("sql attrs = %v", sql)
	}
}
