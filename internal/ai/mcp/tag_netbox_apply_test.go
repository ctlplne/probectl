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

type recordedNetBoxApplyBackend struct{ tenants []string }

func (b *recordedNetBoxApplyBackend) NetBoxTagApply(_ context.Context, p *auth.Principal,
	input NetBoxTagApplyInput) (NetBoxTagApplyResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NetBoxTagApplyResult{AssignmentID: "assignment", ContextID: input.Preview.ContextID,
		TagID: input.Preview.TagID, Value: input.Preview.Value, ReviewedAt: "2026-11-02T21:00:00Z"}, nil
}

func TestNetBoxTagMCPApplyRequiresReviewAndAllGrants(t *testing.T) {
	backend := &recordedNetBoxApplyBackend{}
	server := newTestServer(&fakeBackend{}, testGate(), WithNetBoxTagApplyBackend(backend))
	arguments := NetBoxTagApplyInput{Confirmed: true, ExporterAgentID: "collector",
		ExporterSourceRef: "192.0.2.10", Preview: NetBoxTagPreviewResult{
			ContextID: "11111111-1111-4111-8111-111111111111", TagID: "22222222-2222-4222-8222-222222222222",
			TagKey: "site", TagRevision: "9007199254740993", NetBoxTenantID: "7",
			LookupCIID: "netbox:ipam.ip_address:10", CIID: "netbox:dcim.device:42",
			Name: "owned-edge", Field: "site", Value: "iad", SourceRef: "netbox:t7:ip10:d42:site"}}
	for _, missing := range []string{"tags.read", "tags.write", "cmdb.read"} {
		p := principal("tenant-a", "tags.read", "tags.write", "cmdb.read")
		p.UserID = "reader"
		delete(p.Permissions, missing)
		if listedToolNames(t, handle(t, server, p, 1, "tools/list", nil))["tag_netbox_apply"] {
			t.Fatalf("apply advertised without %s", missing)
		}
		if code, _ := errCode(handle(t, server, p, 2, "tools/call", map[string]any{
			"name": "tag_netbox_apply", "arguments": arguments})); code != codeForbidden || len(backend.tenants) != 0 {
			t.Fatal("denied import reached its backend")
		}
	}
	p := principal("tenant-a", "tags.read", "tags.write", "cmdb.read")
	p.UserID = "reader"
	arguments.Confirmed = false
	if resultOf(t, handle(t, server, p, 3, "tools/call", map[string]any{
		"name": "tag_netbox_apply", "arguments": arguments}))["isError"] != true || len(backend.tenants) != 0 {
		t.Fatal("unconfirmed import reached its backend")
	}
	arguments.Confirmed = true
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p.TenantID = tenant
		if resultOf(t, handle(t, server, p, 4, "tools/call", map[string]any{
			"name": "tag_netbox_apply", "arguments": arguments}))["isError"] == true {
			t.Fatal("confirmed import failed")
		}
	}
	if !reflect.DeepEqual(backend.tenants, []string{"tenant-a", "tenant-b"}) {
		t.Fatalf("apply changed principal tenants: %v", backend.tenants)
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	var hinted map[string]any
	if err := json.Unmarshal(raw, &hinted); err != nil {
		t.Fatal(err)
	}
	hinted["tenant_id"] = "tenant-a"
	if resultOf(t, handle(t, server, p, 5, "tools/call", map[string]any{
		"name": "tag_netbox_apply", "arguments": hinted}))["isError"] != true || len(backend.tenants) != 2 {
		t.Fatal("caller tenant hint reached import backend")
	}
}

func TestNetBoxTagMCPApplyPreviewSchemaMatchesAPIFields(t *testing.T) {
	raw, err := os.ReadFile("../../control/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithNetBoxTagApplyBackend(&recordedNetBoxApplyBackend{}))
	var schema struct {
		Properties map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(server.tools["tag_netbox_apply"].InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	preview := schema.Properties["preview"].Properties
	want := map[string]any{}
	for key, field := range spec.Components.Schemas["NetBoxTagCandidate"].Properties {
		want[key] = field
	}
	for _, key := range []string{"context_id", "tag_id", "tag_key", "tag_revision"} {
		want[key] = spec.Components.Schemas["NetBoxTagPreviewTarget"].Properties[key]
	}
	if !reflect.DeepEqual(want, preview) {
		t.Fatal("MCP reviewed preview fields drifted from the API contract")
	}
}
