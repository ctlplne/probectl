// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type recordedNetBoxTagBackend struct{ tenants []string }

func (b *recordedNetBoxTagBackend) NetBoxTagPreview(_ context.Context, p *auth.Principal,
	input NetBoxTagPreviewInput) (NetBoxTagPreviewResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NetBoxTagPreviewResult{ContextID: input.ContextID, TagID: input.TagID, Field: input.Field, Value: "site"}, nil
}

func TestNetBoxTagMCPRequiresBothReadGrantsAndRejectsTenantHints(t *testing.T) {
	backend := &recordedNetBoxTagBackend{}
	server := newTestServer(&fakeBackend{}, testGate(), WithNetBoxTagBackend(backend),
		WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	arguments := map[string]any{"context_id": "11111111-1111-4111-8111-111111111111",
		"tag_id": "22222222-2222-4222-8222-222222222222", "exporter_agent_id": "collector",
		"exporter_source_ref": "192.0.2.10", "field": "site"}
	for _, permission := range []string{"tags.read", "cmdb.read"} {
		denied := principal("tenant-a", permission)
		denied.UserID = "reader"
		if listedToolNames(t, handle(t, server, denied, 1, "tools/list", nil))["tag_netbox_preview"] {
			t.Fatal("NetBox source tool was advertised without both read grants")
		}
		if code, _ := errCode(handle(t, server, denied, 2, "tools/call", map[string]any{
			"name": "tag_netbox_preview", "arguments": arguments,
		})); code != codeForbidden || len(backend.tenants) != 0 {
			t.Fatalf("denied source read reached backend: code=%d tenants=%v", code, backend.tenants)
		}
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		reader := principal(tenant, "tags.read", "cmdb.read")
		reader.UserID = "reader"
		if !listedToolNames(t, handle(t, server, reader, 3, "tools/list", nil))["tag_netbox_preview"] {
			t.Fatal("authorized source tool missing")
		}
		if resultOf(t, handle(t, server, reader, 4, "tools/call", map[string]any{
			"name": "tag_netbox_preview", "arguments": arguments,
		}))["isError"] == true {
			t.Fatal("authorized source preview failed")
		}
	}
	if len(backend.tenants) != 2 || backend.tenants[0] != "tenant-a" || backend.tenants[1] != "tenant-b" {
		t.Fatalf("MCP source read lost the authenticated tenant: %v", backend.tenants)
	}
	reader := principal("tenant-a", "tags.read", "cmdb.read")
	reader.UserID = "reader"
	arguments["tenant_id"] = "tenant-b"
	if resultOf(t, handle(t, server, reader, 5, "tools/call", map[string]any{
		"name": "tag_netbox_preview", "arguments": arguments,
	}))["isError"] != true || len(backend.tenants) != 2 {
		t.Fatal("caller tenant hint reached NetBox backend")
	}
}

func TestNetBoxTagMCPInputMatchesCommittedAPI(t *testing.T) {
	raw, err := os.ReadFile("../../control/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithNetBoxTagBackend(&recordedNetBoxTagBackend{}))
	var schema map[string]any
	if err := json.Unmarshal(server.tools["tag_netbox_preview"].InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	delete(schema["properties"].(map[string]any), "context_id")
	required := []any{}
	for _, value := range schema["required"].([]any) {
		if value != "context_id" {
			required = append(required, value)
		}
	}
	schema["required"] = required
	if !reflect.DeepEqual(schema, spec.Components.Schemas["NetBoxTagPreviewInput"]) {
		t.Fatal("MCP NetBox preview grammar drifted from the committed API")
	}
}
