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

	"github.com/ctlplne/probectl/internal/auth"
)

func TestNativeInstantStatusKeepsTenantAndRequiresReaderGrants(t *testing.T) {
	const runID = "00000000-0000-4000-8000-000000000034"
	statuses := map[string]string{"tenant-a": "completed", "tenant-b": "running"}
	var calls int
	read := func(_ context.Context, p *auth.Principal, raw json.RawMessage) (json.RawMessage, error) {
		var args struct {
			RunID string `json:"run_id"`
		}
		if err := json.Unmarshal(raw, &args); err != nil || args.RunID != runID {
			t.Fatalf("instant test arguments changed before the reader: %v", err)
		}
		calls++
		return json.Marshal(map[string]string{"state": statuses[p.TenantID]})
	}
	withoutReader := newTestServer(&fakeBackend{}, testGate(), WithInstantTestStatus(nil))
	if _, exists := withoutReader.tools[InstantTestStatusToolName]; exists {
		t.Fatal("registered instant status without a reader")
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithInstantTestStatus(read))
	grants := []string{"test.read", "agent.read", "metrics.read"}
	input := map[string]any{"name": InstantTestStatusToolName, "arguments": map[string]string{"run_id": runID}}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, grants...)
		p.UserID = "operator"
		before := calls
		response := handle(t, server, p, 1, "tools/call", input)
		body, _ := resultOf(t, response)["structuredContent"].(map[string]any)
		if calls != before+1 || body["state"] != statuses[tenant] {
			t.Fatalf("instant test status did not stay under %s: %+v", tenant, response)
		}
		for _, grant := range grants {
			delete(p.Permissions, grant)
			denied := handle(t, server, p, 2, "tools/call", input)
			if code, _ := errCode(denied); code != codeForbidden || calls != before+1 {
				t.Fatalf("instant test status accepted a reader without %s: %+v", grant, denied)
			}
			p.Permissions[grant] = true
		}
		p.UserID = ""
		denied := handle(t, server, p, 3, "tools/call", input)
		if code, _ := errCode(denied); code != codeUnauthorized || calls != before+1 {
			t.Fatalf("instant test status accepted a caller without a user: %+v", denied)
		}
	}
}
