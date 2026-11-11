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

type recordedAlertQuery struct {
	tenants []string
	input   *alert.QuerySourceInput
}

func (b *recordedAlertQuery) AlertQueryGroupGet(_ context.Context, p *auth.Principal, input AlertQueryGroupInput) (alert.QueryGroupInspection, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.QueryGroupInspection{Kind: "current_query_group", RuleID: input.RuleID, GroupKey: input.Group}, nil
}

func (b *recordedAlertQuery) AlertQueryCreate(_ context.Context, p *auth.Principal, input alert.QueryRuleInput) (alert.Rule, error) {
	b.tenants = append(b.tenants, p.TenantID)
	b.input = &input.QuerySource
	return alert.Rule{ID: "11111111-1111-4111-8111-111111111111", TenantID: p.TenantID, Name: input.Name}, nil
}
func (b *recordedAlertQuery) AlertQuerySourceGet(_ context.Context, p *auth.Principal, id string) (alert.QuerySourceState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.QuerySourceState{RuleID: id, Configured: true, Source: b.input}, nil
}
func (b *recordedAlertQuery) AlertQuerySourceSet(ctx context.Context, p *auth.Principal, input AlertQuerySourceInput) (alert.QuerySourceState, error) {
	b.input = input.Input
	return b.AlertQuerySourceGet(ctx, p, input.RuleID)
}
func (b *recordedAlertQuery) AlertQuerySourceClear(_ context.Context, p *auth.Principal, input AlertTagFilterClearInput) (alert.QuerySourceState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.QuerySourceState{RuleID: input.RuleID}, nil
}

func TestSavedQueryAlertMCPRequiresSourceGrantsAndPreservesTenantArguments(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	b := &recordedAlertQuery{input: &alert.QuerySourceInput{ViewID: id, ViewVersion: "9007199254740993", Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "18446744073709551617"}}}
	schemas := map[string]json.RawMessage{}
	for _, name := range []string{"alert_query_create", "alert_query_group_get", "alert_query_source_get", "alert_query_source_set", "alert_query_source_clear"} {
		schemas[name] = json.RawMessage(`{"type":"object"}`)
	}
	s := newTestServer(&fakeBackend{}, testGate(), WithAlertQueryBackend(b, schemas))
	all := []string{"alert.read", "alert.write", "ai.query", "flow.read"}
	for _, missing := range []string{"ai.query", "flow.read"} {
		p := principal("tenant-a", all...)
		p.UserID = "reader"
		delete(p.Permissions, missing)
		for _, name := range []string{"alert_query_group_get", "alert_query_source_get", "alert_query_source_set"} {
			if listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))[name] {
				t.Fatal("source tool visible without current capability", name, missing)
			}
			if code, _ := errCode(handle(t, s, p, 2, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"rule_id": id}})); code != codeForbidden || len(b.tenants) != 0 {
				t.Fatal("missing source grant reached query backend")
			}
		}
	}
	p := principal("tenant-a", all...)
	p.UserID = "writer"
	for _, raw := range []string{
		`{"rule_id":"` + id + `","tenant_id":"foreign","input":{}}`,
		`{"rule_id":"` + id + `","input":{"view_id":"` + id + `","view_version":"1","condition":{"mode":"new_group"},"owner_user_id":"forged"}}`,
		`{"rule_id":"` + id + `","input":null}`,
		`{"rule_id":"` + id + `","input":{"view_id":"` + id + `","view_version":"1","condition":{"mode":"threshold","metric":"bytes:total","comparison":"gt","threshold":18446744073709551617}}}`,
		`{"rule_id":"` + id + `","input":{"view_id":"` + id + `","view_version":"1","condition":{"mode":"new_group","threshold":"1"}}}`,
	} {
		if out := resultOf(t, handle(t, s, p, 3, "tools/call", map[string]any{"name": "alert_query_source_set", "arguments": json.RawMessage(raw)})); out["isError"] != true || len(b.tenants) != 0 {
			t.Fatal("foreign authority or inexact condition reached backend", out)
		}
	}
	if code, _ := errCode(handle(t, s, principal("tenant-a", all...), 4, "tools/call", map[string]any{"name": "alert_query_create", "arguments": map[string]any{"name": "Query", "query_source": b.input}})); code != codeUnauthorized || len(b.tenants) != 0 {
		t.Fatal("non-user caller created a saved-query rule")
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p.TenantID = tenant
		created := resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_query_create", "arguments": map[string]any{"name": "Query alert", "query_source": b.input}}))
		if created["isError"] == true {
			t.Fatal("named native query creation failed", created)
		}
		before := len(b.tenants)
		out := resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_query_source_set", "arguments": map[string]any{"rule_id": id, "input": b.input}}))
		if out["isError"] == true || len(b.tenants) != before+1 || b.tenants[before] != tenant || b.input.Condition.Threshold != "18446744073709551617" || b.input.ViewVersion != "9007199254740993" || b.input.EverySeconds != 60 {
			t.Fatal("native query source lost tenant, exact decimal/revision or schedule", out)
		}
		before = len(b.tenants)
		group := resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_query_group_get", "arguments": map[string]any{"rule_id": id, "group": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}))
		if group["isError"] == true || len(b.tenants) != before+1 || b.tenants[before] != tenant {
			t.Fatal("current group inspection lost actual caller tenant", group)
		}

	}
	clear := principal("tenant-a", "alert.write")
	clear.UserID = "writer"
	for _, confirmed := range []bool{false, true} {
		before := len(b.tenants)
		out := resultOf(t, handle(t, s, clear, 5, "tools/call", map[string]any{"name": "alert_query_source_clear", "arguments": map[string]any{"rule_id": id, "confirmed": confirmed}}))
		if confirmed && (out["isError"] == true || len(b.tenants) != before+1) || !confirmed && (out["isError"] != true || len(b.tenants) != before) {
			t.Fatal("clear confirmation or write-only removal failed", out)
		}
	}
}
