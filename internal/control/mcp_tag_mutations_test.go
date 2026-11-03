// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMCPTagMutationInputsPreserveAPISchemas(t *testing.T) {
	schemas, err := tagMutationToolSchemas()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		tool, api string
		context   bool
	}{
		{"tag_definition_write", "TagDefinitionInput", false},
		{"tag_rule_write", "TagRuleInput", true},
		{"tag_assignment_write", "ManualTagAssignmentInput", true},
	} {
		var envelope struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
			OneOf                []json.RawMessage          `json:"oneOf"`
		}
		if err := json.Unmarshal(schemas[pair.tool], &envelope); err != nil {
			t.Fatal(err)
		}
		var api, nested any
		if err := json.Unmarshal(document.Components.Schemas[pair.api], &api); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(envelope.Properties["input"], &nested); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(api, nested) || envelope.AdditionalProperties || len(envelope.OneOf) != 3 {
			t.Fatalf("%s lost its exact API grammar or action constraints", pair.tool)
		}
		if _, ok := envelope.Properties["context_id"]; ok != pair.context {
			t.Fatalf("%s has wrong context scope", pair.tool)
		}
		for _, forbidden := range []string{"tenant_id", "source", "source_ref", "reviewed_at"} {
			if len(envelope.Properties[forbidden]) != 0 {
				t.Fatalf("%s exposes authority selector %s", pair.tool, forbidden)
			}
		}
	}
}
