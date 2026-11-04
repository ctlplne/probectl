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
	for _, name := range []string{"report_dashboards", "report_schedules", "report_artifacts"} {
		roots[name] = object(map[string]any{})
	}
	for _, name := range []string{"report_dashboard", "report_dashboard_export", "report_artifact_link"} {
		roots[name] = object(map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160}}, "id")
	}
	roots["report_schedule_update"] = object(map[string]any{"id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160}, "enabled": map[string]any{"type": "boolean"}}, "id", "enabled")
	for _, operation := range []struct{ name, path string }{
		{"report_dashboard_save", "/v1/dashboards"},
		{"report_dashboard_import", "/v1/dashboard-manifests/import"},
		{"report_schedule_create", "/v1/dashboard-report-schedules"},
		{"report_generate", "/v1/dashboard-reports"},
	} {
		var op struct {
			RequestBody struct {
				Content map[string]struct {
					Schema json.RawMessage `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		}
		if err := json.Unmarshal(document.Paths[operation.path]["post"], &op); err != nil {
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
		roots[operation.name] = root
	}
	return nativeMCPInputSchemas(document.Components.Schemas, roots)
}
