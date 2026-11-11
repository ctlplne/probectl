// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type peeringBackendProbe struct {
	tenants []string
	input   flow.PeeringEstimateInput
}

func (probe *peeringBackendProbe) PeeringEstimate(_ context.Context, p *auth.Principal, input flow.PeeringEstimateInput) (json.RawMessage, error) {
	probe.tenants = append(probe.tenants, p.TenantID)
	probe.input = input
	return json.Marshal(struct {
		Counter NativePeeringCounter `json:"counter"`
		Source  string               `json:"source"`
	}{NativePeeringCounter("115792089237316195423570985008687907853269984665640564039457584007913129639936"), "operator@example.com"})
}

func peeringNativeArguments() map[string]any {
	return map[string]any{"context_id": tagWriteTestID, "interface_id": tagWriteTestID, "peer_asn": uint32(4294967295), "ix_id": "9223372036854775807", "ix_lan_id": "9007199254740993", "direction": "inbound"}
}

func peeringNativePrincipal(tenant string) *auth.Principal {
	p := principal(tenant, "flow.read", "ai.query", "entities.read", "metrics.read", "events.read")
	p.UserID = "reader"
	return p
}

func TestPeeringNativeToolKeepsExactInputsTenantAndEverySourcePermission(t *testing.T) {
	probe := &peeringBackendProbe{}
	server := newTestServer(&fakeBackend{}, testGate(), WithPeeringEstimateBackend(probe, NativeFlowSchemas{"flow_peering_estimate": json.RawMessage(`{"type":"object"}`)}, func(context.Context, *auth.Principal) (func(), error) { return func() {}, nil }))
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		response := handle(t, server, peeringNativePrincipal(tenant), 1, "tools/call", map[string]any{"name": "flow_peering_estimate", "arguments": peeringNativeArguments()})
		if resultOf(t, response)["isError"] == true || probe.input.PeerASN != 4294967295 || probe.input.IXID != "9223372036854775807" || probe.input.LANID != "9007199254740993" || probe.tenants[len(probe.tenants)-1] != tenant {
			t.Fatal("native peering lost exact input or tenant", response)
		}
		for _, permission := range []string{"flow.read", "ai.query", "entities.read", "metrics.read", "events.read"} {
			p := peeringNativePrincipal(tenant)
			delete(p.Permissions, permission)
			before := len(probe.tenants)
			handle(t, server, p, 2, "tools/call", map[string]any{"name": "flow_peering_estimate", "arguments": peeringNativeArguments()})
			if len(probe.tenants) != before {
				t.Fatal("native peering bypassed a source-plane grant", permission)
			}
		}
		p := peeringNativePrincipal(tenant)
		p.UserID = ""
		before := len(probe.tenants)
		handle(t, server, p, 3, "tools/call", map[string]any{"name": "flow_peering_estimate", "arguments": peeringNativeArguments()})
		if len(probe.tenants) != before {
			t.Fatal("service-only identity reached current-user peering")
		}
	}
	for _, hint := range []string{"tenant_id", "router_id", "complete", "input_digest", "routing_capture_key"} {
		args := peeringNativeArguments()
		args[hint] = "forged"
		raw, _ := json.Marshal(args)
		if _, err := decodePeeringEstimateInput(raw, 2<<20); err == nil {
			t.Fatal("native peering accepted client source authority", hint)
		}
	}
}

func TestPeeringNativeFinalEncodingRetainsFairnessAndExactCountersWithTextRedaction(t *testing.T) {
	probe := &peeringBackendProbe{}
	held, releases := false, 0
	server := newTestServer(&fakeBackend{}, consentGate(map[string]bool{"tenant-a": true}, ai.DefaultRedaction), WithPeeringEstimateBackend(probe, NativeFlowSchemas{"flow_peering_estimate": json.RawMessage(`{"type":"object"}`)}, func(context.Context, *auth.Principal) (func(), error) {
		held = true
		return func() { held = false; releases++ }, nil
	}))
	var request rpcRequest
	if err := json.Unmarshal(nativeRequest("flow_peering_estimate", peeringNativeArguments()), &request); err != nil {
		t.Fatal(err)
	}
	response := server.dispatch(t.Context(), peeringNativePrincipal("tenant-a"), request)
	if !held || response.finalize == nil {
		t.Fatal("peering admission released before final encoding")
	}
	raw := marshal(response)
	if !held || strings.Contains(string(raw), "operator@example.com") {
		t.Fatal("peering encoding released admission or bypassed source text redaction")
	}
	var decoded struct {
		Error  *rpcError `json:"error"`
		Result struct {
			Structured struct {
				Counter string `json:"counter"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Error != nil || decoded.Result.Structured.Counter != "115792089237316195423570985008687907853269984665640564039457584007913129639936" {
		t.Fatal("native peering narrowed or redacted a computed counter", string(raw), err)
	}
	response.finalize()
	if held || releases != 1 {
		t.Fatal("peering admission did not release exactly once")
	}
	for _, bad := range []NativePeeringCounter{"", "01", "-1", "1e10", "operator@example.com", "123-456"} {
		if _, err := json.Marshal(bad); err == nil {
			t.Fatal("arbitrary text became protected peering metadata", bad)
		}
	}
}
