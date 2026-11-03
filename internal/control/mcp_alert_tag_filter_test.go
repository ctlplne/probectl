// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNativeAlertTagSchemasPreserveCompleteAPIGrammarAndExactVersion(t *testing.T) {
	schemas, err := alertTagToolSchemas()
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
	var envelope struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if json.Unmarshal(schemas["alert_tag_filter_set"], &envelope) != nil || len(schemas) != 3 {
		t.Fatal("native alert API input schema is incomplete")
	}
	for _, name := range []string{"AlertTagFilterInput", "FlowQueryFilterGroup", "FlowQueryPredicate"} {
		var got, want any
		api := strings.ReplaceAll(string(document.Components.Schemas[name]), "#/components/schemas/", "#/$defs/")
		if json.Unmarshal(envelope.Definitions[name], &got) != nil || json.Unmarshal([]byte(api), &want) != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("native alert input changed complete API definition %s", name)
		}
	}
	for _, schema := range schemas {
		if strings.Contains(string(schema), "#/components/schemas/") {
			t.Fatal("native alert tool retained an unresolved API reference")
		}
	}
	var config struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(document.Components.Schemas["AlertTagFilter"], &config) != nil {
		t.Fatal("alert filter schema is unavailable")
	}
	var version struct {
		Type     string `json:"type"`
		Constant int    `json:"const"`
		ReadOnly bool   `json:"readOnly"`
	}
	if json.Unmarshal(config.Properties["version"], &version) != nil || version.Type != "integer" || version.Constant != 1 || !version.ReadOnly {
		t.Fatal("alert filter schema relaxed its exact server-authored integer version")
	}
}
