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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tags"
)

const tagWriteTestID = "11111111-1111-4111-8111-111111111111"

type recordedTagMutations struct {
	tenants []string
	value   string
}

func (b *recordedTagMutations) record(p *auth.Principal, action, id string) TagMetadataWriteResult {
	b.tenants = append(b.tenants, p.TenantID)
	if id == "" {
		id = tagWriteTestID
	}
	return TagMetadataWriteResult{Action: action, ID: id}
}

func (b *recordedTagMutations) TagDefinitionWrite(_ context.Context, p *auth.Principal, in TagDefinitionWriteInput) (TagMetadataWriteResult, error) {
	return b.record(p, in.Action, in.ID), nil
}

func (b *recordedTagMutations) TagRuleWrite(_ context.Context, p *auth.Principal, in TagRuleWriteInput) (TagMetadataWriteResult, error) {
	return b.record(p, in.Action, in.ID), nil
}

func (b *recordedTagMutations) ManualTagAssignmentWrite(_ context.Context, p *auth.Principal, in ManualTagAssignmentWriteInput) (TagMetadataWriteResult, error) {
	if in.Input != nil {
		b.value = in.Input.Value
	}
	return b.record(p, in.Action, in.ID), nil
}

func tagWriteMechanicsSchemas() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"tag_definition_write": json.RawMessage(`{"type":"object"}`),
		"tag_rule_write":       json.RawMessage(`{"type":"object"}`),
		"tag_assignment_write": json.RawMessage(`{"type":"object"}`),
	}
}

func TestTagMCPMutationsRequireUserWriteGrantAndExactAction(t *testing.T) {
	backend := &recordedTagMutations{}
	server := newTestServer(&fakeBackend{}, testGate(), WithTagMutationBackend(backend, tagWriteMechanicsSchemas()))
	writer := principal("tenant-a", "tags.write")
	writer.UserID = "writer"
	for _, name := range []string{"tag_definition_write", "tag_rule_write", "tag_assignment_write"} {
		if !listedToolNames(t, handle(t, server, writer, 1, "tools/list", nil))[name] {
			t.Fatalf("writer cannot discover %s", name)
		}
		for _, denied := range []*auth.Principal{principal("tenant-a", "tags.read"), principal("tenant-a", "tags.write")} {
			if denied.Has("tags.read") {
				denied.UserID = "reader"
			}
			if listedToolNames(t, handle(t, server, denied, 2, "tools/list", nil))[name] {
				t.Fatal("mutation exposed without a user write grant")
			}
			if code, _ := errCode(handle(t, server, denied, 3, "tools/call", map[string]any{
				"name": name, "arguments": map[string]any{"action": "delete", "id": tagWriteTestID, "confirmed": true, "context_id": tagWriteTestID},
			})); code != codeForbidden && code != codeUnauthorized {
				t.Fatalf("denied mutation code=%d", code)
			}
		}
	}
	if len(backend.tenants) != 0 {
		t.Fatal("denied callers reached the mutation backend")
	}
	for _, raw := range []string{
		`{"action":"delete","id":"` + tagWriteTestID + `"}`,
		`{"action":"delete","id":"` + tagWriteTestID + `","confirmed":false}`,
		`{"action":"delete","id":"` + tagWriteTestID + `","confirmed":true,"input":null}`,
		`{"action":"create","id":"","input":{"key":"customer"}}`,
		`{"action":"create","input":{"key":"customer","tenant_id":"tenant-b"}}`,
		`{"action":"create","input":{"Key":"customer"}}`,
		`{"action":"create","action":"delete","input":{"key":"customer"}}`,
		`{"action":"update","id":"` + tagWriteTestID + `"}`,
	} {
		if resultOf(t, handle(t, server, writer, 4, "tools/call", map[string]any{
			"name": "tag_definition_write", "arguments": json.RawMessage(raw),
		}))["isError"] != true || len(backend.tenants) != 0 {
			t.Fatalf("ambiguous, unconfirmed or hinted mutation reached backend: %s", raw)
		}
	}
	for _, name := range []string{"tag_definition_write", "tag_rule_write", "tag_assignment_write"} {
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			writer.TenantID = tenant
			for _, action := range []string{"create", "update", "delete"} {
				before := len(backend.tenants)
				args := map[string]any{"action": action}
				if name != "tag_definition_write" {
					args["context_id"] = tagWriteTestID
				}
				if action != "create" {
					args["id"] = tagWriteTestID
				}
				if action == "delete" {
					args["confirmed"] = true
				} else {
					args["input"] = map[string]any{}
				}
				if resultOf(t, handle(t, server, writer, 5, "tools/call", map[string]any{
					"name": name, "arguments": args,
				}))["isError"] == true || len(backend.tenants) != before+1 || backend.tenants[before] != tenant {
					t.Fatalf("valid %s %s lost the authenticated tenant", name, action)
				}
			}
		}
	}
}

func TestTagMCPMutationAdmitsFullEscapedValueWithinItsOwnBound(t *testing.T) {
	backend := &recordedTagMutations{}
	server := newTestServer(&fakeBackend{}, testGate(), WithTagMutationBackend(backend, tagWriteMechanicsSchemas()))
	p := principal("tenant-a", "tags.write")
	p.UserID = "writer"
	raw := json.RawMessage(`{"action":"create","context_id":"` + tagWriteTestID + `","input":{"tag_id":"` + tagWriteTestID + `","target_kind":"device","target_id":"` + tagWriteTestID + `","value":"` + strings.Repeat(`\ud83c\udf10`, tags.MaxValueCharacters) + `"}}`)
	if len(raw) > tags.MaxValueInputBytes {
		t.Fatal("complete supported escaped value exceeds its declared write bound")
	}
	if resultOf(t, handle(t, server, p, 1, "tools/call", map[string]any{
		"name": "tag_assignment_write", "arguments": raw,
	}))["isError"] == true || backend.value != strings.Repeat("🌐", tags.MaxValueCharacters) {
		t.Fatal("MCP shortened or refused the complete escaped tag value")
	}
	raw = json.RawMessage(`{"action":"create","context_id":"` + tagWriteTestID + `","input":{"source":"netbox","value":"forged"}}`)
	if resultOf(t, handle(t, server, p, 2, "tools/call", map[string]any{
		"name": "tag_assignment_write", "arguments": raw,
	}))["isError"] != true || len(backend.tenants) != 1 {
		t.Fatal("manual mutation accepted imported provenance")
	}
	oversize := strings.Repeat("x", tags.MaxValueInputBytes)
	if resultOf(t, handle(t, server, p, 3, "tools/call", map[string]any{
		"name": "tag_assignment_write", "arguments": map[string]any{"action": "create", "context_id": tagWriteTestID, "input": map[string]any{"value": oversize}},
	}))["isError"] != true || len(backend.tenants) != 1 {
		t.Fatal("metadata argument byte bound did not stop an oversized write")
	}
}

func TestTagMCPMutationsStayHiddenWithoutCompleteContracts(t *testing.T) {
	server := newTestServer(&fakeBackend{}, testGate(), WithTagMutationBackend(&recordedTagMutations{}, nil))
	p := principal("tenant-a", "tags.write")
	p.UserID = "writer"
	if listedToolNames(t, handle(t, server, p, 1, "tools/list", nil))["tag_definition_write"] {
		t.Fatal("missing schemas exposed an uncontracted mutation")
	}
}
