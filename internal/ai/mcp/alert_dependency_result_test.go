// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
)

func TestDependencyNativeResultKeepsCompleteReferencesAndTextRedaction(t *testing.T) {
	// This valid UUID contains a checksum-shaped numeric prefix. Configuration
	// references must remain usable, while the same bytes in free text mask.
	const id = "40000000-0000-4004-8000-abcdefabcdef"
	state := alert.DependencyPolicyState{RuleID: id, Configured: true, Policy: &alert.DependencyPolicyInput{ContextID: id, FreshnessSeconds: 300, Graph: &alert.DependencyGraphInput{Nodes: []alert.DependencyNodeInput{
		{EntityID: id, AgentID: id, TestID: id, Parents: []string{}},
		{EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AgentID: id, TestID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Parents: []string{id}},
	}}}}
	server := nativeProbeServer(&nativeBackendProbe{}, nil)
	old, err := server.redactedToolResult(id, state, true)
	if err != nil {
		t.Fatal(err)
	}
	var damaged alert.DependencyPolicyState
	if json.Unmarshal(old["structuredContent"].(json.RawMessage), &damaged) != nil || reflect.DeepEqual(damaged, state) {
		t.Fatal("fixture no longer reproduces generic text masking of structural identity")
	}
	value, err := dependencyNativeResult(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.redactedToolResult(id, map[string]any{"configuration": value, "untrusted": "password=local-fixture-only " + id}, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := result["structuredContent"].(json.RawMessage)
	var got struct {
		Configuration alert.DependencyPolicyState `json:"configuration"`
		Untrusted     string                      `json:"untrusted"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got.Configuration, state) {
		t.Fatal("native result changed exact configuration references, order or complete parent edges", err)
	}
	if bytes.Contains(raw, []byte("local-fixture-only")) || !bytes.Contains(raw, []byte("[secret:")) || !bytes.Contains(raw, []byte("[pan:")) {
		t.Fatal("configuration encoding weakened untrusted text redaction")
	}
	text := result["content"].([]map[string]any)[0]["text"].(string)
	if !bytes.Equal([]byte(text), raw) {
		t.Fatal("native text and structured configuration disagree")
	}
	denied := errors.New("backend denied current source")
	if value, err := dependencyNativeResult(state, denied); value != nil || !errors.Is(err, denied) {
		t.Fatal("refused backend result disclosed configuration")
	}
	state.Policy.Graph.Nodes[0].AgentID = "password=untrusted"
	value, err = dependencyNativeResult(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.redactedToolResult(id, value, true); err == nil {
		t.Fatal("malformed reference acquired structural metadata encoding")
	}
}
