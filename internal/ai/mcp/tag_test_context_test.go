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

type recordedTestTagBackend struct{ tenants []string }

func (b *recordedTestTagBackend) TestTagAdmission(context.Context, *auth.Principal) (func(), error) {
	return func() {}, nil
}

func (b *recordedTestTagBackend) TestTagContext(_ context.Context, p *auth.Principal, input tags.TestContextInput) (tags.TestContextResolution, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return tags.TestContextResolution{TagRevision: "9007199254740993", AsOf: "2026-11-03T00:00:00Z", Items: []tags.SubjectResolution{{TargetKind: "test", TargetID: input.TestIDs[0], ContextID: "owned-context", TagRevision: "9007199254740993", AsOf: "2026-11-03T00:00:00Z", Items: []tags.EffectiveItem{{TagID: "key", Key: "customer", Value: "owned-" + p.TenantID, Source: "rule"}}}}}, nil
}

func TestTestTagMCPRequiresUserBothReadGrantsAndStrictIdentityInput(t *testing.T) {
	b := &recordedTestTagBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithTestTagBackend(b), WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	args := map[string]any{"test_ids": []string{"owned-test"}}
	for _, permissions := range [][]string{{"tags.read"}, {"test.read"}, {}} {
		p := principal("tenant-a", permissions...)
		p.UserID = "reader"
		if listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))["test_tag_context"] {
			t.Fatal("test tag tool visible without both read grants")
		}
		if code, _ := errCode(handle(t, s, p, 2, "tools/call", map[string]any{"name": "test_tag_context", "arguments": args})); code != codeForbidden || len(b.tenants) != 0 {
			t.Fatal("missing read grant reached test metadata")
		}
	}
	if code, _ := errCode(handle(t, s, principal("tenant-a", "tags.read", "test.read"), 3, "tools/call", map[string]any{"name": "test_tag_context", "arguments": args})); code != codeUnauthorized || len(b.tenants) != 0 {
		t.Fatal("non-user caller reached test metadata")
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, "tags.read", "test.read")
		p.UserID = "reader"
		for _, hint := range []string{"tenant_id", "context_id", "target", "name", "sys_name"} {
			if resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "test_tag_context", "arguments": map[string]any{"test_ids": []string{"owned-test"}, hint: "forged"}}))["isError"] != true || len(b.tenants) != 0 {
				t.Fatal("scope or fact hint reached the test backend")
			}
		}
		response := resultOf(t, handle(t, s, p, 5, "tools/call", map[string]any{"name": "test_tag_context", "arguments": args}))
		encoded, err := json.Marshal(response)
		if err != nil || response["isError"] == true || len(b.tenants) != 1 || b.tenants[0] != tenant || !strings.Contains(string(encoded), "9007199254740993") || !strings.Contains(string(encoded), "owned-"+tenant) {
			t.Fatal("native test context lost tenant, exact revision or curated value")
		}
		b.tenants = nil
	}
}
