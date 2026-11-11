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

func TestNativeAlertEvaluationSchemaDerivesQueryBoundsFromAPI(t *testing.T) {
	raw, err := alertEvaluationToolSchema()
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Additional bool                       `json:"additionalProperties"`
		Required   []string                   `json:"required"`
	}
	if json.Unmarshal(raw, &schema) != nil || len(schema.Properties) != 3 || schema.Additional || len(schema.Required) != 1 || schema.Required[0] != "rule_id" {
		t.Fatal("receipt input schema is incomplete or accepts authority hints")
	}
	var document struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string          `json:"name"`
					Schema json.RawMessage `json:"schema"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if json.Unmarshal(openapiJSON, &document) != nil {
		t.Fatal("missing API schema")
	}
	for _, parameter := range document.Paths["/v1/alerts/{id}/evaluations"].Get.Parameters {
		if parameter.Name != "fingerprint" && parameter.Name != "limit" {
			continue
		}
		var got, want any
		if json.Unmarshal(schema.Properties[parameter.Name], &got) != nil || json.Unmarshal(parameter.Schema, &want) != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("native receipt constraint differs from API: %s", parameter.Name)
		}
	}
}

func TestNativeSavedQueryAlertSchemasKeepExactDecimalAndClosedAuthority(t *testing.T) {
	schemas, err := alertQueryToolSchemas()
	if err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 4 {
		t.Fatal("saved-query create/read/set/clear schemas incomplete")
	}
	for _, schema := range schemas {
		if !json.Valid(schema) || strings.Contains(string(schema), "#/components/schemas/") {
			t.Fatal("unresolved saved-query native input schema")
		}
	}
	var input struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(schemas["alert_query_source_set"], &input); err != nil {
		t.Fatal(err)
	}
	var source struct {
		Properties map[string]any `json:"properties"`
		Additional bool           `json:"additionalProperties"`
	}
	if json.Unmarshal(input.Definitions["AlertQuerySourceInput"], &source) != nil || source.Additional || len(source.Properties) != 4 || source.Properties["owner_user_id"] != nil || source.Properties["read_grants"] != nil {
		t.Fatal("native saved source accepted authority hints")
	}
	var condition struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
	}
	if json.Unmarshal(input.Definitions["AlertQueryCondition"], &condition) != nil || condition.Properties["threshold"].Type != "string" {
		t.Fatal("native threshold was rounded into a JSON number")
	}
}
