// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

func TestMCPServerColdABACLoadFailureFailsClosed(t *testing.T) {
	pool := newClosedABACCache(t).pool
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	egress := ai.NewEgressGate(func(context.Context, string) (bool, error) {
		return true, nil
	}, nil, ai.RedactionPolicy{})
	srv := NewMCPServer(
		&config.Config{AIMaxEvidence: 10},
		log,
		pool,
		pathstore.NewMemory(),
		120,
		egress,
		nil,
		nil,
	)
	principal := &auth.Principal{
		TenantID:    "tenant-a",
		Permissions: map[string]bool{"test.read": true},
	}

	for id, tc := range []struct {
		request []byte
		message string
	}{
		{
			request: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
			message: "authorization policy is temporarily unavailable",
		},
		{
			request: []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_tests"}}`),
			// The closed pool also prevents the mandatory mcp.tool_call append.
			// For invocation, audit unavailability is the outer fail-closed
			// reason and the tool still never runs.
			message: "durable audit is temporarily unavailable",
		},
	} {
		var response map[string]any
		if err := json.Unmarshal(srv.Handle(context.Background(), principal, tc.request), &response); err != nil {
			t.Fatalf("request %d response: %v", id+1, err)
		}
		rpcErr, ok := response["error"].(map[string]any)
		if !ok {
			t.Fatalf("request %d reached MCP data handling without ABAC policies: %v", id+1, response)
		}
		if code, _ := rpcErr["code"].(float64); int(code) != -32004 {
			t.Fatalf("request %d error code = %v, want -32004 unavailable", id+1, rpcErr["code"])
		}
		if message, _ := rpcErr["message"].(string); message != tc.message {
			t.Fatalf("request %d exposed an unstable policy error: %q", id+1, message)
		}
	}
}

func TestMCPServerWithoutPolicyStoreFailsClosed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	egress := ai.NewEgressGate(func(context.Context, string) (bool, error) {
		return true, nil
	}, nil, ai.RedactionPolicy{})
	srv := NewMCPServer(
		&config.Config{AIMaxEvidence: 10},
		log,
		nil,
		pathstore.NewMemory(),
		120,
		egress,
		nil,
		nil,
	)
	principal := &auth.Principal{
		TenantID:    "tenant-a",
		Permissions: map[string]bool{"test.read": true},
	}

	var response map[string]any
	raw := srv.Handle(context.Background(), principal, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	rpcErr, ok := response["error"].(map[string]any)
	if !ok {
		t.Fatalf("MCP without an ABAC policy store advertised tools: %v", response)
	}
	if code, _ := rpcErr["code"].(float64); int(code) != -32004 {
		t.Fatalf("MCP without policy store code = %v, want -32004", rpcErr["code"])
	}
}
