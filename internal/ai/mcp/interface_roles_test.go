// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
)

type roleConfigurationProbe struct {
	tenants []string
	command InterfaceRoleCommand
}

func (b *roleConfigurationProbe) InterfaceRoleConfiguration(_ context.Context, p *auth.Principal, _ string, input InterfaceRoleCommand) (json.RawMessage, error) {
	b.tenants = append(b.tenants, p.TenantID)
	b.command = input
	return json.RawMessage(`{"revision":"9007199254740993"}`), nil
}
func roleMechanicsSchemas() NativeFlowSchemas {
	out := NativeFlowSchemas{}
	for _, name := range []string{"interface_role_explain", "interface_role_policy", "interface_role_policy_set", "interface_role_override", "interface_role_override_set", "interface_role_override_reset"} {
		out[name] = json.RawMessage(`{"type":"object"}`)
	}
	return out
}

func TestInterfaceRoleNativeToolsPreserveCompleteInputAndUserTenantBoundary(t *testing.T) {
	b := &roleConfigurationProbe{}
	s := newTestServer(&fakeBackend{}, testGate(), WithInterfaceRoleBackend(b, roleMechanicsSchemas(), 16<<20))
	definition := entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{4294967295}, CustomerASNs: []uint32{64501}, DescriptionRules: []entity.InterfaceRoleDescriptionRule{}}
	for i := 0; i < 4097; i++ {
		definition.DescriptionRules = append(definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{Pattern: strings.Repeat("uplink-", 160) + fmt.Sprint(i), Role: entity.InterfaceRoleBackbone})
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, "agent.write", "entities.read")
		p.UserID = "writer"
		args := map[string]any{"context_id": tagWriteTestID, "expected_id": tagWriteTestID, "expected_revision": "9007199254740993", "definition": definition}
		raw, _ := json.Marshal(args)
		if len(raw) <= 4<<20 {
			t.Fatal("complete native policy fixture lost its intended population")
		}
		response := handle(t, s, p, 1, "tools/call", map[string]any{"name": "interface_role_policy_set", "arguments": args})
		if response["result"] == nil {
			t.Fatal("native policy retained an obsolete envelope ceiling or changed complete tenant input")
		}
		if resultOf(t, response)["isError"] == true || b.command.ExpectedRevision != "9007199254740993" || len(b.command.Definition.DescriptionRules) != 4097 || b.tenants[len(b.tenants)-1] != tenant {
			t.Fatal("native policy retained an obsolete envelope ceiling or changed complete tenant input")
		}
		for i, rule := range b.command.Definition.DescriptionRules {
			if rule.Pattern != definition.DescriptionRules[i].Pattern {
				t.Fatal("native policy dropped or reordered a description rule")
			}
		}
		for _, name := range []string{"interface_role_policy_set", "interface_role_override_set", "interface_role_override_reset"} {
			denied := principal(tenant, "entities.read")
			denied.UserID = "reader"
			before := len(b.tenants)
			handle(t, s, denied, 2, "tools/call", map[string]any{"name": name, "arguments": args})
			service := principal(tenant, "agent.write")
			handle(t, s, service, 3, "tools/call", map[string]any{"name": name, "arguments": args})
			if len(b.tenants) != before {
				t.Fatal("role write reached backend without a tenant-user write grant")
			}
		}
	}
	for _, raw := range []string{
		`{"context_id":"` + tagWriteTestID + `","tenant_id":"foreign"}`,
		`{"context_id":"` + tagWriteTestID + `","Context_ID":"` + tagWriteTestID + `"}`,
		`{"context_id":"` + tagWriteTestID + `","interface_id":"` + tagWriteTestID + `","expected_id":"` + tagWriteTestID + `","expected_revision":"1","confirmed":false}`,
	} {
		if _, err := decodeInterfaceRoleCommand(json.RawMessage(raw), "interface_role_override_reset", 16<<20); err == nil {
			t.Fatal("native role configuration accepted authority hints, aliases or unconfirmed reset")
		}
	}
	budget := DefaultNativeFlowRenderBudget()
	budget.SourceBytes = 1 << 20
	WithNativeFlowRenderBudget(budget)(s)
	p := principal("tenant-a", "agent.write")
	p.UserID = "writer"
	before := len(b.tenants)
	handle(t, s, p, 4, "tools/call", map[string]any{"name": "interface_role_policy_set", "arguments": map[string]any{"context_id": tagWriteTestID, "expected_revision": "0", "definition": definition}})
	if len(b.tenants) != before {
		t.Fatal("lower positive native profile admitted an oversized complete request")
	}
}

func TestInterfaceRoleNativeExplanationRequiresEverySourceBeforeBackend(t *testing.T) {
	b := &roleConfigurationProbe{}
	s := newTestServer(&fakeBackend{}, testGate(), WithInterfaceRoleBackend(b, roleMechanicsSchemas(), 16<<20))
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		args := map[string]any{"context_id": tagWriteTestID, "interface_id": tagWriteTestID}
		for _, missing := range []string{"", "entities.read", "metrics.read", "events.read", "user"} {
			p := principal(tenant, "entities.read", "metrics.read", "events.read")
			p.UserID = "reader"
			if missing == "user" {
				p.UserID = ""
			} else {
				delete(p.Permissions, missing)
			}
			before := len(b.tenants)
			reply := handle(t, s, p, 1, "tools/call", map[string]any{"name": "interface_role_explain", "arguments": args})
			if missing == "" {
				if reply["result"] == nil || resultOf(t, reply)["isError"] == true || len(b.tenants) != before+1 || b.tenants[before] != tenant || b.command.InterfaceID != tagWriteTestID {
					t.Fatal("native explanation lost the owned complete request", reply)
				}
			} else if len(b.tenants) != before {
				t.Fatal("native explanation reached facts without every source and current user grant", missing)
			}
		}
	}
}
