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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type recordedAlertTags struct {
	tenants []string
	input   *alert.TagFilterInput
}

func (*recordedAlertTags) AlertTagAdmission(context.Context, *auth.Principal) (func(), error) {
	return func() {}, nil
}

func (b *recordedAlertTags) AlertTagFilterGet(_ context.Context, p *auth.Principal, id string) (alert.TagFilterState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.TagFilterState{RuleID: id, HasTagFilter: true, TagFilter: &alert.TagFilter{Version: 1, TargetKind: "test", TagRevision: "9007199254740993", Filter: b.input.Filter}}, nil
}

func (b *recordedAlertTags) AlertTagFilterSet(ctx context.Context, p *auth.Principal, input AlertTagFilterInput) (alert.TagFilterState, error) {
	b.input = input.Input
	return b.AlertTagFilterGet(ctx, p, input.RuleID)
}

func (b *recordedAlertTags) AlertTagFilterClear(_ context.Context, p *auth.Principal, input AlertTagFilterClearInput) (alert.TagFilterState, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return alert.TagFilterState{RuleID: input.RuleID}, nil
}

func TestAlertTagMCPRequiresCurrentUserEverySourceGrantAndStrictArguments(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	wide := strings.Repeat("🌐", 24000)
	b := &recordedAlertTags{input: &alert.TagFilterInput{TargetKind: "test", Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{wide}}}}}}
	schemas := map[string]json.RawMessage{}
	for _, name := range []string{"alert_tag_filter_get", "alert_tag_filter_set", "alert_tag_filter_clear"} {
		schemas[name] = json.RawMessage(`{"type":"object"}`)
	}
	s := newTestServer(&fakeBackend{}, testGate(), WithAlertTagBackend(b, schemas))
	all := []string{"alert.read", "alert.write", "tags.read", "test.read", "metrics.read"}
	for _, name := range []string{"alert_tag_filter_get", "alert_tag_filter_set"} {
		for _, missing := range []string{"tags.read", "test.read", "metrics.read"} {
			p := principal("tenant-a", all...)
			p.UserID = "reader"
			delete(p.Permissions, missing)
			if listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))[name] {
				t.Fatalf("%s visible without %s", name, missing)
			}
			if code, _ := errCode(handle(t, s, p, 2, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"rule_id": id}})); code != codeForbidden || len(b.tenants) != 0 {
				t.Fatal("missing source grant reached alert metadata backend")
			}
		}
	}
	for _, name := range []string{"alert_tag_filter_get", "alert_tag_filter_set", "alert_tag_filter_clear"} {
		if code, _ := errCode(handle(t, s, principal("tenant-a", all...), 3, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"rule_id": id}})); code != codeUnauthorized || len(b.tenants) != 0 {
			t.Fatal("non-user caller reached alert metadata")
		}
	}
	p := principal("tenant-a", all...)
	p.UserID = "writer"
	for _, raw := range []string{
		`{"rule_id":"` + id + `","owner_user_id":"forged","input":{"target_kind":"test","filter":{}}}`,
		`{"rule_id":"` + id + `","input":{"target_kind":"test","filter":{},"tenant_id":"foreign"}}`,
		`{"rule_id":"` + id + `","Input":{"target_kind":"test","filter":{}}}`,
		`{"rule_id":"` + id + `","input":null}`,
		`{"rule_id":"not-owned-id","input":{"target_kind":"test","filter":{}}}`,
	} {
		if resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_tag_filter_set", "arguments": json.RawMessage(raw)}))["isError"] != true || len(b.tenants) != 0 {
			t.Fatal("hinted, ambiguous or invalid alert metadata input reached backend")
		}
	}
	for _, confirmed := range []any{nil, false, "true"} {
		if resultOf(t, handle(t, s, p, 5, "tools/call", map[string]any{"name": "alert_tag_filter_clear", "arguments": map[string]any{"rule_id": id, "confirmed": confirmed}}))["isError"] != true || len(b.tenants) != 0 {
			t.Fatal("unconfirmed metadata clear reached backend")
		}
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p.TenantID = tenant
		for _, name := range []string{"alert_tag_filter_set", "alert_tag_filter_get", "alert_tag_filter_clear"} {
			args := map[string]any{"rule_id": id}
			if name == "alert_tag_filter_set" {
				args["input"] = b.input
			}
			if name == "alert_tag_filter_clear" {
				args["confirmed"] = true
			}
			before := len(b.tenants)
			out := resultOf(t, handle(t, s, p, 6, "tools/call", map[string]any{"name": name, "arguments": args}))
			encoded, err := json.Marshal(out)
			if err != nil || out["isError"] == true || len(b.tenants) != before+1 || b.tenants[before] != tenant {
				t.Fatal("native alert operation lost authenticated tenant")
			}
			if name != "alert_tag_filter_clear" && (!strings.Contains(string(encoded), wide) || !strings.Contains(string(encoded), "9007199254740993")) {
				t.Fatal("native alert criteria lost complete value or exact revision")
			}
			if name == "alert_tag_filter_clear" && (strings.Contains(string(encoded), wide) || strings.Contains(string(encoded), `"tag_filter"`)) {
				t.Fatal("clear response disclosed previous metadata")
			}
		}
	}
	clearOnly := principal("tenant-a", "alert.write")
	clearOnly.UserID = "writer"
	if !listedToolNames(t, handle(t, s, clearOnly, 7, "tools/list", nil))["alert_tag_filter_clear"] {
		t.Fatal("loss of metadata reads hid explicit clear")
	}
	if resultOf(t, handle(t, s, clearOnly, 8, "tools/call", map[string]any{"name": "alert_tag_filter_clear", "arguments": map[string]any{"rule_id": id, "confirmed": true}}))["isError"] == true {
		t.Fatal("authorized clear required revoked source reads")
	}
	hidden := newTestServer(&fakeBackend{}, testGate(), WithAlertTagBackend(b, nil))
	if listedToolNames(t, handle(t, hidden, p, 9, "tools/list", nil))["alert_tag_filter_get"] {
		t.Fatal("missing API schemas exposed native alert tools")
	}
}
