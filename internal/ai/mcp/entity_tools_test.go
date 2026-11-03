// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type recordedEntityBackend struct{ tenants []string }

func (b *recordedEntityBackend) EntityContextList(_ context.Context, p *auth.Principal, _ EntityContextListInput) (EntityContextListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityContextListResult{Items: []EntityContextResult{}}, nil
}

type recordedPrefixBackend struct{ recordedEntityBackend }

func (b *recordedPrefixBackend) EntityNetworkPrefixSet(_ context.Context, p *auth.Principal, in EntityNetworkPrefixInput) (EntityItemResult, error) {
	if in.NetworkPrefix == nil {
		return EntityItemResult{}, errors.New("explicit network field required")
	}
	b.tenants = append(b.tenants, p.TenantID)
	return EntityItemResult{ID: in.ID, ContextID: in.ContextID, Kind: "prefix", NetworkPrefix: *in.NetworkPrefix}, nil
}

func TestPrefixNetworkMCPRequiresUserWriteGrantAndRejectsTenantHints(t *testing.T) {
	old := newTestServer(&fakeBackend{}, testGate(), WithEntityBackend(&recordedEntityBackend{}))
	writer := principal("tenant-a", "agent.write")
	writer.UserID = "operator"
	if listedToolNames(t, handle(t, old, writer, 1, "tools/list", nil))["entity_network_prefix_set"] {
		t.Fatal("older backend advertised unsupported write")
	}
	b := &recordedPrefixBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithEntityBackend(b), WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	reader := principal("tenant-a", "entities.read")
	reader.UserID = "reader"
	if listedToolNames(t, handle(t, s, reader, 2, "tools/list", nil))["entity_network_prefix_set"] {
		t.Fatal("reader saw prefix write")
	}
	args := map[string]any{"context_id": "own-context", "id": "stable-prefix", "network_prefix": "2001:db8::/32"}
	if code, _ := errCode(handle(t, s, reader, 3, "tools/call", map[string]any{"name": "entity_network_prefix_set", "arguments": args})); code != codeForbidden || len(b.tenants) != 0 {
		t.Fatal("missing write grant reached prefix backend")
	}
	for i, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, "agent.write")
		p.UserID = "operator"
		if !listedToolNames(t, handle(t, s, p, 4+i, "tools/list", nil))["entity_network_prefix_set"] {
			t.Fatal("writer missing prefix tool")
		}
		if resultOf(t, handle(t, s, p, 6+i, "tools/call", map[string]any{"name": "entity_network_prefix_set", "arguments": args}))["isError"] == true || len(b.tenants) != i+1 || b.tenants[i] != tenant {
			t.Fatal("prefix tool lost authenticated tenant")
		}
	}
	for i, bad := range []map[string]any{
		{"context_id": "own-context", "id": "stable-prefix"},
		{"context_id": "own-context", "id": "stable-prefix", "network_prefix": nil},
		{"context_id": "own-context", "id": "stable-prefix", "network_prefix": "", "tenant_id": "tenant-b"},
	} {
		if resultOf(t, handle(t, s, writer, 10+i, "tools/call", map[string]any{"name": "entity_network_prefix_set", "arguments": bad}))["isError"] != true || len(b.tenants) != 2 {
			t.Fatal("invalid/missing explicit network or tenant hint accepted")
		}
	}
	args["network_prefix"] = ""
	if resultOf(t, handle(t, s, writer, 20, "tools/call", map[string]any{"name": "entity_network_prefix_set", "arguments": args}))["isError"] == true || len(b.tenants) != 3 {
		t.Fatal("explicit clear was refused")
	}
}
func (b *recordedEntityBackend) EntityContextCreate(_ context.Context, p *auth.Principal, _ EntityContextCreateInput) (EntityContextResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityContextResult{}, nil
}
func (b *recordedEntityBackend) EntityCreate(_ context.Context, p *auth.Principal, _ EntityCreateInput) (EntityItemResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityItemResult{}, nil
}

func (b *recordedEntityBackend) EntityList(_ context.Context, p *auth.Principal, _ EntityListInput) (EntityListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityListResult{Items: []EntityItemResult{}}, nil
}
func (b *recordedEntityBackend) EntityGet(_ context.Context, p *auth.Principal, _ EntityGetInput) (EntityItemResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityItemResult{}, nil
}
func (b *recordedEntityBackend) EntityEvidenceList(_ context.Context, p *auth.Principal, _ EntityDetailListInput) (EntityEvidenceListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityEvidenceListResult{Items: []EntityEvidenceResult{}}, nil
}
func (b *recordedEntityBackend) EntityLinkList(_ context.Context, p *auth.Principal, _ EntityDetailListInput) (EntityLinkListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityLinkListResult{Items: []EntityLinkResult{}}, nil
}
func (b *recordedEntityBackend) EntityResolve(_ context.Context, p *auth.Principal, _ EntityResolveInput) (EntityResolutionResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityResolutionResult{Status: "unresolved"}, nil
}
func (b *recordedEntityBackend) EntityAssign(_ context.Context, p *auth.Principal, _ EntityAssignInput) (EntityAssignmentResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityAssignmentResult{}, nil
}
func (b *recordedEntityBackend) EntityPathContextAssign(_ context.Context, p *auth.Principal, _ EntityPathContextInput) (EntityPathContextResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityPathContextResult{}, nil
}
func (b *recordedEntityBackend) EntityPathResolve(_ context.Context, p *auth.Principal, _ EntityPathResolveInput) (EntityPathResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return EntityPathResult{Status: "unbound", Items: []EntityPathHopResult{}}, nil
}

func TestEntityMCPAuthorizationPrecedesBackend(t *testing.T) {
	b := &recordedEntityBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithEntityBackend(b),
		WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	reader := principal("tenant-a", "entities.read")
	reader.UserID = "reader"
	if got := listedToolNames(t, handle(t, s, reader, 1, "tools/list", nil)); !got["entity_list"] || !got["entity_context_list"] ||
		!got["entity_evidence_list"] || !got["entity_link_list"] ||
		got["entity_source_assign"] || got["entity_context_create"] || got["entity_create"] || got["entity_path_context_assign"] {
		t.Fatalf("reader tool catalog=%v", got)
	}
	if code, _ := errCode(handle(t, s, reader, 2, "tools/call", map[string]any{
		"name": "entity_source_assign", "arguments": map[string]any{"context_id": "ctx"},
	})); code != codeForbidden || len(b.tenants) != 0 {
		t.Fatalf("reader reached entity assignment: code=%d tenants=%v", code, b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 3, "tools/call", map[string]any{
		"name": "entity_list", "arguments": map[string]any{"context_id": "ctx"},
	}))["isError"] == true || len(b.tenants) != 1 || b.tenants[0] != "tenant-a" {
		t.Fatalf("authorized entity list did not preserve tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 4, "tools/call", map[string]any{
		"name": "entity_list", "arguments": map[string]any{"context_id": "ctx", "tenant_id": "tenant-b"},
	}))["isError"] != true || len(b.tenants) != 1 {
		t.Fatalf("caller-supplied tenant hint reached backend: %v", b.tenants)
	}
}
