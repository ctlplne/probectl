// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestNativeRoutingTransferKeepsTenantAndRequiresCurrentReaderGrants(t *testing.T) {
	schema := json.RawMessage(`{"type":"object"}`)
	var tenants []string
	read := func(_ context.Context, p *auth.Principal, raw json.RawMessage) (json.RawMessage, error) {
		var input struct {
			Prefix string `json:"prefix"`
		}
		if err := json.Unmarshal(raw, &input); err != nil || input.Prefix != "203.0.113.0/24" {
			t.Fatalf("routing transfer inputs changed before the owned reader: %v", err)
		}
		tenants = append(tenants, p.TenantID)
		return json.RawMessage(`{"status":"estimated"}`), nil
	}
	for _, disabled := range []Option{WithRoutingTransferEstimate(schema, nil), WithRoutingTransferEstimate(nil, read)} {
		server := newTestServer(&fakeBackend{}, testGate(), disabled)
		if _, exists := server.tools[RoutingTransferToolName]; exists {
			t.Fatal("registered routing transfer without its input schema and reader")
		}
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithRoutingTransferEstimate(schema, read))
	grants := []string{"ai.query", "flow.agreements.read", "topology.read", "flow.read", "entities.read", "metrics.read", "events.read"}
	input := map[string]any{
		"name":      RoutingTransferToolName,
		"arguments": map[string]any{"prefix": "203.0.113.0/24"},
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p := principal(tenant, grants...)
		p.UserID = "operator"
		before := len(tenants)
		response := handle(t, server, p, 1, "tools/call", input)
		if response["error"] != nil || resultOf(t, response)["isError"] == true || len(tenants) != before+1 {
			t.Fatalf("authorized routing transfer did not reach its reader: %+v", response)
		}
		delete(p.Permissions, "events.read")
		handle(t, server, p, 2, "tools/call", input)
		if len(tenants) != before+1 {
			t.Fatal("routing transfer accepted a reader without the event grant")
		}
	}
	if !slices.Equal(tenants, []string{"tenant-a", "tenant-b"}) {
		t.Fatal("route estimates were dispatched under another tenant", tenants)
	}
}
