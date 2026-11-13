// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func (p *releaseFlowReport) provePacketImpactClients(t *testing.T, input incident.ImpactInput, command, ca string, foreign *releaseFlowReport) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	p.packetImpactInput = raw
	var request sdk.IncidentImpactInput
	var expected sdk.IncidentImpactResponse
	if json.Unmarshal(raw, &request) != nil || json.Unmarshal(p.packetImpact, &expected) != nil {
		t.Fatal("real packet impact lost its SDK contract")
	}
	client := sdk.NewClient(p.api.base, sdk.WithHTTPClient(p.api.client), sdk.WithToken(p.api.token))
	actual, err := client.GetIncidentImpact(t.Context(), sdk.GetIncidentImpactRequest{Id: p.packetIncident, Body: &request})
	if err != nil || actual == nil {
		t.Fatal("real packet impact SDK request failed", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, actual.EvaluatedAt); err != nil {
		t.Fatal("real packet impact SDK lost its evaluation clock", err)
	}
	actual.EvaluatedAt, expected.EvaluatedAt = "", ""
	if !reflect.DeepEqual(*actual, expected) {
		t.Fatal("real packet impact SDK changed the complete counters, customer or original citations")
	}
	file := filepath.Join(t.TempDir(), "packet-impact.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output, code := p.runCLI(t, command, ca, "incident", "impact", p.packetIncident, "--body-file", file)
	if code != 0 {
		t.Fatal("built real packet incident impact CLI failed")
	}
	assertPacketImpactJSON(t, p.packetImpact, output)
	other := sdk.NewClient(foreign.api.base, sdk.WithHTTPClient(foreign.api.client), sdk.WithToken(foreign.api.token))
	if response, err := other.GetIncidentImpact(t.Context(), sdk.GetIncidentImpactRequest{Id: p.packetIncident, Body: &request}); err == nil || response != nil {
		t.Fatal("real packet incident impact SDK crossed tenant storage")
	}
	if _, code := foreign.runCLI(t, command, ca, "incident", "impact", p.packetIncident, "--body-file", file); code == 0 {
		t.Fatal("built real packet incident impact CLI crossed tenant storage")
	}
}

func assertPacketImpactJSON(t *testing.T, expected, actual []byte) {
	t.Helper()
	decode := func(raw []byte) map[string]any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal("real packet impact surface returned invalid JSON", err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatal("real packet impact surface returned trailing content")
		}
		clock, ok := value["evaluated_at"].(string)
		if _, err := time.Parse(time.RFC3339Nano, clock); !ok || err != nil {
			t.Fatal("real packet impact surface lost its evaluation clock")
		}
		// Each request evaluates current authority anew. All other fields,
		// including freshness deadlines and complete citations, must agree.
		delete(value, "evaluated_at")
		return value
	}
	if !reflect.DeepEqual(decode(expected), decode(actual)) {
		t.Fatal("real packet impact surface changed the complete response")
	}
}

func (p *releaseFlowReport) provePacketImpactNative(t *testing.T, base, token string, foreign *releaseFlowReport) {
	t.Helper()
	var args map[string]any
	if json.Unmarshal(p.packetImpactInput, &args) != nil {
		t.Fatal("real packet impact native input is unavailable")
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		for _, own := range []bool{true, false} {
			args["incident_id"] = p.packetIncident
			if !own {
				args["incident_id"] = foreign.packetIncident
			}
			params := map[string]any{"name": "incident_impact", "arguments": args}
			if wire == "2026-07-28" {
				params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
			}
			raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
				"MCP-Protocol-Version": wire, "Mcp-Method": "tools/call", "Mcp-Name": "incident_impact", "X-Probectl-Tenant": foreign.tenant} {
				req.Header.Set(key, value)
			}
			response, err := p.api.client.Do(req)
			if err != nil {
				t.Fatal("real packet impact native TLS request failed")
			}
			raw, err = io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal("real packet impact native response was incomplete", err)
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
					IsError    bool                       `json:"isError"`
					ResultType string                     `json:"resultType"`
					Meta       map[string]json.RawMessage `json:"_meta"`
					Data       json.RawMessage            `json:"structuredContent"`
					Content    []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			if json.Unmarshal(raw, &reply) != nil {
				t.Fatal("real packet impact native response lost its complete RPC frame", wire, response.StatusCode)
			}
			failed := len(reply.Error) != 0 && string(reply.Error) != "null" || reply.Result.IsError
			if !own {
				if !failed || len(reply.Result.Data) != 0 && string(reply.Result.Data) != "null" || bytes.Contains(raw, []byte(foreign.packetPrefixCustomer)) {
					t.Fatal("real packet impact native call disclosed a foreign incident", wire)
				}
				continue
			}
			if response.StatusCode != http.StatusOK || failed || len(reply.Result.Content) != 1 ||
				!bytes.Equal(bytes.TrimSpace([]byte(reply.Result.Content[0].Text)), bytes.TrimSpace(reply.Result.Data)) {
				t.Fatal("real packet impact native text and structured content disagree", wire)
			}
			if wire == "2026-07-28" && (reply.Result.ResultType != "complete" || len(reply.Result.Meta["io.modelcontextprotocol/serverInfo"]) == 0) ||
				wire == "2025-11-25" && (reply.Result.ResultType != "" || len(reply.Result.Meta) != 0) {
				t.Fatal("real packet impact native result lost its protocol contract", wire)
			}
			assertPacketImpactJSON(t, p.packetImpact, reply.Result.Data)
		}
	}
}
