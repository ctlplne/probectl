// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type routingBindingProbe struct {
	tenants []string
	command BGPRoutingBindingCommand
	write   bool
}

func (b *routingBindingProbe) BGPRoutingBindings(_ context.Context, actor *auth.Principal, write bool, input BGPRoutingBindingCommand) (json.RawMessage, error) {
	b.tenants = append(b.tenants, actor.TenantID)
	b.command, b.write = input, write
	return json.RawMessage(`{"accepted":true}`), nil
}

func TestBGPRoutingNativeToolsKeepCompleteInputAndTenantUserBoundary(t *testing.T) {
	backend := &routingBindingProbe{}
	schemas := NativeFlowSchemas{"bgp_routing_bindings": json.RawMessage(`{"type":"object"}`), "bgp_routing_bindings_replace": json.RawMessage(`{"type":"object"}`)}
	server := newTestServer(&fakeBackend{}, testGate(), WithBGPRoutingBindingBackend(backend, schemas, 1<<20))
	bindings := []map[string]any{
		{"context_id": tagWriteTestID, "router_id": tagWriteTestID, "distinguisher": "ffffffffffffffff", "bgp_identifier": "0.0.0.0", "families": []int{2, 1}, "source_format": "frr_loc_rib_v1"},
		{"context_id": tagWriteTestID, "router_id": tagWriteTestID, "distinguisher": "0000000000000000", "bgp_identifier": "192.0.2.1", "families": []int{1}},
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		actor := principal(tenant, "entities.read", "agent.write")
		actor.UserID = "current-owner"
		args := map[string]any{"context_id": tagWriteTestID, "collector_agent_id": "collector", "source_ref": "origin", "expected_epoch": "", "bindings": bindings}
		result := handle(t, server, actor, 1, "tools/call", map[string]any{"name": "bgp_routing_bindings_replace", "arguments": args})
		if result["result"] == nil || resultOf(t, result)["isError"] == true || !backend.write || backend.command.Bindings == nil || backend.command.ExpectedEpoch == nil || *backend.command.ExpectedEpoch != "" || backend.tenants[len(backend.tenants)-1] != tenant {
			t.Fatal("native routing bindings lost complete input or caller tenant")
		}
		want, _ := json.Marshal(bindings)
		if string(*backend.command.Bindings) != string(want) {
			t.Fatal("native routing bindings changed complete protocol values")
		}
		for _, p := range []*auth.Principal{principal(tenant, "entities.read"), principal(tenant, "agent.write")} {
			before := len(backend.tenants)
			handle(t, server, p, 2, "tools/call", map[string]any{"name": "bgp_routing_bindings_replace", "arguments": args})
			if len(backend.tenants) != before {
				t.Fatal("native routing write reached backend without a tenant-user write grant")
			}
		}
		delete(args, "bindings")
		delete(args, "expected_epoch")
		result = handle(t, server, actor, 3, "tools/call", map[string]any{"name": "bgp_routing_bindings", "arguments": args})
		if result["result"] == nil || resultOf(t, result)["isError"] == true || backend.write || backend.command.ContextID != tagWriteTestID {
			t.Fatal("native routing read lost its complete owned source selector")
		}
	}
}

func TestBGPRoutingNativeParserRefusesAuthorityHintsAndIncompleteReplacement(t *testing.T) {
	base := `"context_id":"` + tagWriteTestID + `","collector_agent_id":"collector","source_ref":"origin"`
	for _, raw := range []string{
		`{` + base + `,"tenant_id":"foreign","expected_epoch":"","bindings":[]}`,
		`{` + base + `,"expected_epoch":""}`,
		`{` + base + `,"bindings":[]}`,
		`{` + base + `,"expected_epoch":"","bindings":null}`,
		`{` + base + `,"expected_epoch":"","bindings":{}}`,
		`{` + base + `,"expected_epoch":"foreign","bindings":[]}`,
		`{"context_id":"foreign","collector_agent_id":"collector","source_ref":"origin","expected_epoch":"","bindings":[]}`,
	} {
		if _, err := decodeBGPRoutingBindingCommand(json.RawMessage(raw), true, 1<<20); err == nil {
			t.Fatal("native routing configuration accepted authority hints or a partial replacement")
		}
	}
	valid := json.RawMessage(`{` + base + `,"expected_epoch":"","bindings":[]}`)
	if _, err := decodeBGPRoutingBindingCommand(valid, false, 1<<20); err == nil {
		t.Fatal("native routing read accepted a mutation body")
	}
	if _, err := decodeBGPRoutingBindingCommand(valid, true, 1); err == nil {
		t.Fatal("native routing replacement bypassed positive request admission")
	}
}
