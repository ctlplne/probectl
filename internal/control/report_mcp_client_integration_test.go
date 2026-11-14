// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type reportMCPClient struct {
	protocolVersion string
	t               *testing.T
	socket          *httptest.Server
	foreignTenant   string
}

func (c reportMCPClient) call(token, tool string, args any, target any, want bool, marker string) json.RawMessage {
	c.t.Helper()
	wire := c.protocolVersion
	if wire == "" {
		wire = "2026-07-28"
	}
	params := map[string]any{"name": tool, "arguments": args}
	if wire == "2026-07-28" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		c.t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(c.t.Context(), http.MethodPost, c.socket.URL, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	for key, value := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": "Bearer " + token, "MCP-Protocol-Version": wire, "Mcp-Method": "tools/call", "Mcp-Name": tool, "X-Probectl-Tenant": c.foreignTenant} {
		request.Header.Set(key, value)
	}
	client := c.socket.Client()
	client.Timeout = 30 * time.Second
	response, err := client.Do(request)
	if err != nil {
		c.t.Fatal("actual report MCP transport failed", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		c.t.Fatal("report MCP response exceeded fixture transport envelope", err)
	}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		var final []byte
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("data: ")) {
				final = bytes.TrimPrefix(line, []byte("data: "))
			}
		}
		raw = final
	}
	var reply struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool            `json:"isError"`
			Data    json.RawMessage `json:"structuredContent"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		c.t.Fatal("report MCP returned a non-JSON frame", response.StatusCode)
	}
	ok := response.StatusCode == http.StatusOK && len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null"
	if ok != want {
		c.t.Fatal(marker, "success", ok, "wanted", want)
	}
	if !ok {
		if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
			c.t.Fatal("refused report MCP exposed structured data")
		}
		return nil
	}
	data := reply.Result.Data
	for _, key := range []string{`"source_capture"`, `"content":`, `"permissions":`, `"contexts":`} {
		if bytes.Contains(data, []byte(key)) {
			c.t.Fatal("report MCP exposed private body or source requirements")
		}
	}
	if bytes.Contains(data, []byte(token)) {
		c.t.Fatal("report MCP exposed its bearer credential")
	}
	if len(reply.Result.Content) != 1 {
		c.t.Fatal("report MCP did not return one complete text projection")
	}
	var text, structured bytes.Buffer
	if json.Compact(&text, []byte(reply.Result.Content[0].Text)) != nil || json.Compact(&structured, data) != nil || !bytes.Equal(text.Bytes(), structured.Bytes()) {
		c.t.Fatal("report MCP text and structured metadata disagree")
	}
	if target != nil {
		if err := json.Unmarshal(data, target); err != nil {
			c.t.Fatal("decode actual report MCP projection", err)
		}
	}
	return data
}
