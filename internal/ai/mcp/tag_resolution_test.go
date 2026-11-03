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
	"github.com/ctlplne/probectl/internal/tags"
)

type recordedTagSubjectBackend struct{ tenants []string }

func (b *recordedTagSubjectBackend) TagSubjectResolve(_ context.Context, p *auth.Principal, input TagSubjectInput) (tags.SubjectResolution, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return tags.SubjectResolution{ContextID: input.ContextID, TargetKind: input.TargetKind, TagRevision: "9007199254740993", Items: []tags.EffectiveItem{}}, nil
}

func TestEffectiveTagMCPRequiresTenantUserGrantAndStrictReference(t *testing.T) {
	b := &recordedTagSubjectBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithTagSubjectBackend(b),
		WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	args := map[string]any{"context_id": "context", "target_kind": "device", "target_id": "subject"}
	missingGrant := principal("tenant-a")
	missingGrant.UserID = "denied-reader"
	for _, tc := range []struct {
		principal *auth.Principal
		code      int
	}{{missingGrant, codeForbidden}, {principal("tenant-a", "tags.read"), codeUnauthorized}} {
		p := tc.principal
		if listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))["tag_subject_resolve"] {
			t.Fatal("read tool visible without tenant user and tags.read")
		}
		if code, _ := errCode(handle(t, s, p, 2, "tools/call", map[string]any{"name": "tag_subject_resolve", "arguments": args})); code != tc.code || len(b.tenants) != 0 {
			t.Fatalf("unauthorized subject call: code=%d want=%d backend_calls=%d", code, tc.code, len(b.tenants))
		}
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, "tags.read")
		p.UserID = "reader"
		for _, extra := range []string{"tenant_id", "address", "sys_descr", "names"} {
			input := map[string]any{"context_id": "context", "target_kind": "device", "target_id": "subject", extra: "forged"}
			if resultOf(t, handle(t, s, p, 3, "tools/call", map[string]any{"name": "tag_subject_resolve", "arguments": input}))["isError"] != true || len(b.tenants) != 0 {
				t.Fatal("fact or tenant substitution reached backend")
			}
		}
		if resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "tag_subject_resolve", "arguments": args}))["isError"] == true {
			t.Fatal("authorized subject lookup failed")
		}
		if b.tenants[len(b.tenants)-1] != tenant {
			t.Fatal("subject lookup lost authenticated tenant")
		}
		// Keep the strict-input checks independent in the next tenant lane.
		b.tenants = nil
	}
}
