// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type recordedTagBackend struct{ tenants []string }

func (b *recordedTagBackend) TagDefinitionList(_ context.Context, p *auth.Principal) (TagDefinitionListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return TagDefinitionListResult{Items: []TagDefinitionResult{{ID: "tag-id", Key: "customer"}}}, nil
}

func (b *recordedTagBackend) TagRuleList(_ context.Context, p *auth.Principal,
	_ TagContextListInput) (TagRuleListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return TagRuleListResult{Items: []TagRuleResult{}}, nil
}

func (b *recordedTagBackend) TagAssignmentList(_ context.Context, p *auth.Principal,
	_ TagContextListInput) (TagAssignmentListResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return TagAssignmentListResult{Items: []TagAssignmentResult{}}, nil
}

func TestTagMCPReadToolsRequireTenantPermissionAndContext(t *testing.T) {
	b := &recordedTagBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithTagBackend(b),
		WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	reader := principal("tenant-a", "tags.read")
	reader.UserID = "reader"
	if got := listedToolNames(t, handle(t, s, reader, 1, "tools/list", nil)); !got["tag_definition_list"] || !got["tag_rule_list"] ||
		!got["tag_assignment_list"] {
		t.Fatalf("tag reader catalog=%v", got)
	}
	denied := principal("tenant-a")
	denied.UserID = "denied"
	if got := listedToolNames(t, handle(t, s, denied, 2, "tools/list", nil)); got["tag_definition_list"] || got["tag_rule_list"] || got["tag_assignment_list"] {
		t.Fatalf("tag tools exposed without tags.read: %v", got)
	}
	if code, _ := errCode(handle(t, s, denied, 3, "tools/call", map[string]any{
		"name": "tag_definition_list", "arguments": map[string]any{},
	})); code != codeForbidden || len(b.tenants) != 0 {
		t.Fatalf("unauthorized caller reached tag backend: code=%d tenants=%v", code, b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 4, "tools/call", map[string]any{
		"name": "tag_rule_list", "arguments": map[string]any{"context_id": "context-a"},
	}))["isError"] == true || len(b.tenants) != 1 || b.tenants[0] != "tenant-a" {
		t.Fatalf("authorized tag read lost tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 5, "tools/call", map[string]any{
		"name": "tag_assignment_list", "arguments": map[string]any{
			"context_id": "context-a", "tenant_id": "tenant-b"},
	}))["isError"] != true || len(b.tenants) != 1 {
		t.Fatalf("caller tenant hint reached tag backend: %v", b.tenants)
	}
}
