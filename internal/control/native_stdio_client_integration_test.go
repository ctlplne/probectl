// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
)

type interfaceRoleStdioClient struct {
	input   *io.PipeWriter
	decoder *json.Decoder
}

func openInterfaceRoleStdio(t *testing.T, server *mcp.Server, authenticator mcp.Authenticator, token, wire string, lifetime ...time.Duration) *interfaceRoleStdioClient {
	t.Helper()
	duration := 2 * time.Minute
	if len(lifetime) > 0 {
		duration = lifetime[0]
	}
	ctx, cancel := context.WithTimeout(t.Context(), duration)
	initial, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()
	closePipes := func() { _ = inputR.Close(); _ = inputW.Close(); _ = outputR.Close(); _ = outputW.Close() }
	done := make(chan error, 1)
	go func() { <-ctx.Done(); closePipes() }()
	go func() {
		defer outputW.Close()
		done <- server.ServeAuthenticatedStdio(ctx, inputR, outputW, initial, func(ctx context.Context) (*auth.Principal, error) { return authenticator.Authenticate(ctx, token) })
	}()
	t.Cleanup(func() {
		_ = inputW.Close()
		select {
		case err := <-done:
			if err != nil && ctx.Err() == nil {
				t.Error("role stdio did not drain cleanly", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("role stdio did not drain before cleanup")
		}
		cancel()
		closePipes()
	})
	client := &interfaceRoleStdioClient{input: inputW, decoder: json.NewDecoder(outputR)}
	if wire == "2025-11-25" {
		frame, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-role-client", "version": "1"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inputW.Write(append(frame, '\n')); err != nil {
			t.Fatal(err)
		}
		var initialized struct {
			Result struct {
				Version string `json:"protocolVersion"`
			} `json:"result"`
		}
		if client.decoder.Decode(&initialized) != nil || initialized.Result.Version != wire {
			t.Fatal("role stdio did not negotiate its legacy revision")
		}
		if _, err := inputW.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")); err != nil {
			t.Fatal(err)
		}
	}
	return client
}

func (c *interfaceRoleStdioClient) call(t *testing.T, wire, tool string, args, target any, wantOK bool) {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args}
	if wire == "2026-07-28" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	frame, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.input.Write(append(frame, '\n')); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError    bool            `json:"isError"`
			ResultType string          `json:"resultType"`
			Data       json.RawMessage `json:"structuredContent"`
			Content    []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := c.decoder.Decode(&reply); err != nil {
		t.Fatal("role stdio lost its complete RPC frame", err)
	}
	ok := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
	if ok != wantOK {
		t.Fatalf("role stdio current authority mismatch for %s: success=%v expected=%v", tool, ok, wantOK)
	}
	if !ok {
		if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
			t.Fatal("refused role stdio frame disclosed structured data")
		}
		return
	}
	if (wire == "2026-07-28" && reply.Result.ResultType != "complete") || (wire == "2025-11-25" && reply.Result.ResultType != "") {
		t.Fatal("role stdio result used the wrong protocol revision")
	}
	if len(reply.Result.Content) != 1 || strings.TrimSpace(reply.Result.Content[0].Text) != strings.TrimSpace(string(reply.Result.Data)) {
		t.Fatal("role stdio text and structured results disagree")
	}
	if target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
		t.Fatal("role stdio lost its typed complete result")
	}
}
