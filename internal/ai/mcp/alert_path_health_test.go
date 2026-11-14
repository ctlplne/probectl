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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
)

type recordedAlertPathHealth struct {
	tenants []string
	input   *alert.PathHealthSourceInput
}

func (b *recordedAlertPathHealth) AlertPathHealthCreate(_ context.Context, p *auth.Principal, input alert.PathHealthRuleInput) (alert.Rule, error) {
	b.tenants = append(b.tenants, p.TenantID)
	b.input = &input.PathHealthSource
	return alert.Rule{ID: "11111111-1111-4111-8111-111111111111", TenantID: p.TenantID, Name: input.Name}, nil
}
func (b *recordedAlertPathHealth) AlertPathHealthGet(_ context.Context, p *auth.Principal, id string) (alert.PathHealthSourceState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.PathHealthSourceState{RuleID: id, Configured: true, Source: b.input}, nil
}
func (b *recordedAlertPathHealth) AlertPathHealthSet(ctx context.Context, p *auth.Principal, input AlertPathHealthInput) (alert.PathHealthSourceState, error) {
	b.input = input.Input
	return b.AlertPathHealthGet(ctx, p, input.RuleID)
}
func (b *recordedAlertPathHealth) AlertPathHealthClear(_ context.Context, p *auth.Principal, input AlertTagFilterClearInput) (alert.PathHealthSourceState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.PathHealthSourceState{RuleID: input.RuleID}, nil
}
func TestPathHealthAlertMCPRequiresCurrentSourceGrantsAndActualTenant(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	b := &recordedAlertPathHealth{input: &alert.PathHealthSourceInput{TestID: id, InterfaceID: "22222222-2222-4222-8222-222222222222", Metric: "probectl.device.if.in.fcs.errors"}}
	schemas := map[string]json.RawMessage{}
	for _, name := range []string{"alert_path_health_create", "alert_path_health_get", "alert_path_health_set", "alert_path_health_clear"} {
		schemas[name] = json.RawMessage(`{"type":"object"}`)
	}
	s := newTestServer(&fakeBackend{}, testGate(), WithAlertPathHealthBackend(b, schemas))
	all := []string{"alert.read", "alert.write", "ai.query", "test.read", "entities.read", "metrics.read"}
	for _, missing := range []string{"ai.query", "test.read", "entities.read", "metrics.read"} {
		p := principal("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", all...)
		p.UserID = "reader"
		delete(p.Permissions, missing)
		for _, name := range []string{"alert_path_health_create", "alert_path_health_get", "alert_path_health_set"} {
			if listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))[name] {
				t.Fatal("source tool visible without current grant", name, missing)
			}
			if code, _ := errCode(handle(t, s, p, 2, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"rule_id": id}})); code != codeForbidden || len(b.tenants) != 0 {
				t.Fatal("missing source grant reached backend")
			}
		}
	}
	p := principal("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", all...)
	p.UserID = "writer"
	for _, raw := range []string{
		`{"rule_id":"` + id + `","tenant_id":"foreign","input":{}}`,
		`{"rule_id":"` + id + `","input":{"test_id":"` + id + `","interface_id":"` + id + `","owner_user_id":"forged"}}`,
		`{"rule_id":"` + id + `","input":null}`,
		`{"rule_id":"` + id + `","input":{"test_id":"` + id + `","interface_id":"` + id + `","metric":"bytes"}}`,
	} {
		if out := resultOf(t, handle(t, s, p, 3, "tools/call", map[string]any{"name": "alert_path_health_set", "arguments": json.RawMessage(raw)})); out["isError"] != true || len(b.tenants) != 0 {
			t.Fatal("forged authority or unsupported counter reached backend", out)
		}
	}
	for _, tenant := range []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
		p.TenantID = tenant
		for _, op := range []struct {
			name string
			args any
		}{
			{"alert_path_health_create", map[string]any{"name": "Original error climb", "path_health_source": b.input}},
			{"alert_path_health_set", map[string]any{"rule_id": id, "input": b.input}},
			{"alert_path_health_get", map[string]any{"rule_id": id}},
		} {
			before := len(b.tenants)
			out := resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": op.name, "arguments": op.args}))
			if out["isError"] == true || len(b.tenants) != before+1 || b.tenants[before] != tenant || b.input.Metric != "probectl.device.if.in.fcs.errors" || b.input.LookbackSeconds != 86400 {
				t.Fatal("native source lost actual tenant or canonical inputs", out)
			}
		}
	}
	p = principal("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alert.write")
	p.UserID = "writer"
	for _, confirmed := range []bool{false, true} {
		before := len(b.tenants)
		out := resultOf(t, handle(t, s, p, 5, "tools/call", map[string]any{"name": "alert_path_health_clear", "arguments": map[string]any{"rule_id": id, "confirmed": confirmed}}))
		if confirmed && (out["isError"] == true || len(b.tenants) != before+1) || !confirmed && (out["isError"] != true || len(b.tenants) != before) {
			t.Fatal("clear confirmation or write-only cleanup failed", out)
		}
	}
}
