// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// DPR-193: `next_safe_action.kind` is a CLOSED enum in the OpenAPI document and
// a typed union in the web client, and the handlers had drifted out of both.
// Three kinds the control plane emits — inspect_identity, reenroll_identity
// (added for DPR-176 hours before this test) and inspect_collector_input — were
// absent from the spec's enum. Nothing noticed: `openapi-gate` checks that every
// documented route exists, not that a documented enum still contains every value
// its handler can produce. A generated SDK, a validating client or a strict
// proxy would have rejected a response the product legitimately sends, and the
// operator would have seen an empty next step on exactly the rows that have one.
//
// So the enum is derived from the source rather than repeated here: every
// safeAction( call site in this package must be in the spec, and every value in
// the spec must be reachable from one.
func TestNextSafeActionKindsMatchTheOpenAPIEnum(t *testing.T) {
	emitted := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`safeAction\("([a-z_]+)"`)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(src), -1) {
			emitted[m[1]] = true
		}
	}
	if len(emitted) < 5 {
		t.Fatalf("found only %d safeAction kinds in this package — the scan is broken, not the code", len(emitted))
	}

	var spec struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("openapi.json does not parse: %v", err)
	}
	// FleetSafeAction by name: the spec has a dozen other `kind` enums (readiness
	// actions, coverage actions, threat rules) and a substring match on "action"
	// swept four of them in, which is how a contract test starts reporting other
	// people's business as this package's drift.
	const schemaName = "FleetSafeAction"
	schema, ok := spec.Components.Schemas[schemaName]
	if !ok {
		t.Fatalf("openapi.json has no %s schema — the fleet view's response is undocumented", schemaName)
	}
	var fleetAction struct {
		Properties struct {
			Kind struct {
				Enum []string `json:"enum"`
			} `json:"kind"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &fleetAction); err != nil {
		t.Fatalf("%s does not parse: %v", schemaName, err)
	}
	documented := map[string]bool{}
	for _, v := range fleetAction.Properties.Kind.Enum {
		documented[v] = true
	}
	if len(documented) == 0 {
		t.Fatalf("%s.properties.kind has no enum — the closed set this test defends does not exist", schemaName)
	}

	for _, k := range sortedKeys(emitted) {
		if !documented[k] {
			t.Errorf("the control plane emits next_safe_action.kind %q and openapi.json's enum does not allow it — "+
				"a validating client would reject the response", k)
		}
	}
	for _, k := range sortedKeys(documented) {
		if !emitted[k] {
			t.Errorf("openapi.json documents next_safe_action.kind %q and nothing in this package emits it — "+
				"either the handler was removed or the name is a typo", k)
		}
	}
}

// And the web client's union is the third copy of the same list. A value the API
// sends and the client's type does not name is a label that renders as nothing.
func TestNextSafeActionKindsMatchTheWebClientUnion(t *testing.T) {
	src, err := os.ReadFile("../../web/src/api/agents.ts")
	if err != nil {
		t.Skipf("web client not present: %v", err)
	}
	s := string(src)
	start := strings.Index(s, "next_safe_action")
	if start < 0 {
		t.Fatal("next_safe_action not found in web/src/api/agents.ts")
	}
	end := strings.Index(s[start:], "label: string")
	if end < 0 {
		t.Fatal("could not bound the next_safe_action kind union")
	}
	union := s[start : start+end]

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`safeAction\("([a-z_]+)"`)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(raw), -1) {
			if !strings.Contains(union, "'"+m[1]+"'") {
				t.Errorf("the API emits next_safe_action.kind %q and web/src/api/agents.ts does not name it — "+
					"the row's next step renders blank", m[1])
			}
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
