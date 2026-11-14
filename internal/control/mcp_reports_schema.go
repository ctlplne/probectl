// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"

	"github.com/ctlplne/probectl/internal/ai/mcp"
)

func reportToolSchemas() (mcp.NativeFlowSchemas, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	object := func(properties map[string]any, required ...string) map[string]any {
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	}
	roots := map[string]any{}
	for _, name := range []string{"report_dashboards", "report_schedules"} {
		roots[name] = object(map[string]any{})
	}
	var inbox struct {
		Parameters []struct {
			Name   string          `json:"name"`
			In     string          `json:"in"`
			Schema json.RawMessage `json:"schema"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(document.Paths["/v1/dashboard-report-artifacts"]["get"], &inbox); err != nil {
		return nil, err
	}
	properties := map[string]any{}
	for _, parameter := range inbox.Parameters {
		if parameter.In == "query" {
			var schema any
			if err := json.Unmarshal(parameter.Schema, &schema); err != nil {
				return nil, err
			}
			properties[parameter.Name] = schema
		}
	}
	roots["report_artifacts"] = object(properties)
	for _, name := range []string{"report_dashboard", "report_dashboard_export", "report_artifact_link"} {
		roots[name] = object(map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160}}, "id")
	}
	for _, operation := range []struct{ name, path, method string }{
		{"report_dashboard_save", "/v1/dashboards", "post"},
		{"report_dashboard_import", "/v1/dashboard-manifests/import", "post"},
		{"report_schedule_create", "/v1/dashboard-report-schedules", "post"},
		{"report_generate", "/v1/dashboard-reports", "post"},
		{"report_schedule_update", "/v1/dashboard-report-schedules/{id}", "patch"},
	} {
		var op struct {
			RequestBody struct {
				Content map[string]struct {
					Schema json.RawMessage `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		}
		if err := json.Unmarshal(document.Paths[operation.path][operation.method], &op); err != nil {
			return nil, err
		}
		var root any
		schema := op.RequestBody.Content["application/json"].Schema
		if len(schema) == 0 {
			return nil, errors.New("report tool request schema is unavailable")
		}
		if err := json.Unmarshal(schema, &root); err != nil {
			return nil, err
		}
		if operation.name == "report_schedule_update" {
			patch, ok := root.(map[string]any)
			if !ok {
				return nil, errors.New("report patch schema is not an object")
			}
			fields, ok := patch["properties"].(map[string]any)
			if !ok {
				return nil, errors.New("report patch schema has no fields")
			}
			fields["id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 160}
			patch["required"] = []string{"id"}
		}
		roots[operation.name] = root
	}
	return nativeMCPInputSchemas(document.Components.Schemas, roots)
}
