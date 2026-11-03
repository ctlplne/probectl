// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
)

// Native schemas resolve the committed API's complete reachable definitions.
// No second field/operator grammar or remote schema/data fetch is introduced.
func nativeFlowToolSchemas() (mcp.NativeFlowSchemas, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	components := document.Components.Schemas
	object := func(properties map[string]any, required ...string) map[string]any {
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	}
	ref := func(name string) map[string]any { return map[string]any{"$ref": "#/components/schemas/" + name} }
	text := func(maximum int) map[string]any { return map[string]any{"type": "string", "maxLength": maximum} }
	version := map[string]any{"type": "string", "pattern": "^[1-9][0-9]{0,18}$", "maxLength": 19}
	id := text(128)
	roots := map[string]any{}
	roots["flow_explorer_plan"] = ref("FlowQuestionInput")
	roots["flow_explorer_schema"] = object(map[string]any{})
	roots["flow_explorer_query"] = object(map[string]any{"plan": ref("FlowQueryOptions")}, "plan")
	roots["flow_explorer_compare"] = object(map[string]any{"plan": ref("FlowQueryOptions"), "previous_from": map[string]any{"type": "string", "format": "date-time"}, "previous_to": map[string]any{"type": "string", "format": "date-time"}}, "plan", "previous_from", "previous_to")
	for _, name := range []string{"flow_explorer_page", "flow_explorer_comparison_page"} {
		roots[name] = object(map[string]any{"cursor": text(4096)}, "cursor")
	}
	var csvInput map[string]any
	if err := json.Unmarshal(components["FlowSnapshotMCPExportInput"], &csvInput); err != nil {
		return nil, errors.New("native CSV input schema is unavailable")
	}
	roots["flow_explorer_csv"] = csvInput
	roots["flow_filter_list"] = object(map[string]any{"after": text(128), "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}})
	for _, name := range []string{"flow_filter_get", "flow_view_get", "flow_view_run"} {
		roots[name] = object(map[string]any{"id": id}, "id")
	}
	var filter map[string]any
	if json.Unmarshal(components["FlowSavedFilterInput"], &filter) != nil {
		return nil, errors.New("native filter schema is unavailable")
	}
	properties, ok := filter["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("native filter properties are unavailable")
	}
	delete(properties, "version_text")
	properties["version"] = version
	properties["id"] = id
	filter["description"] = "Create without id/version; update with id and the exact observed decimal-text version. Tenant scope and resource budgets are server-owned. Full nested API filter grammar and fail-closed audit apply."
	roots["flow_filter_save"] = filter
	for _, name := range []string{"flow_filter_delete", "flow_view_delete"} {
		roots[name] = object(map[string]any{"id": id, "version": version}, "id", "version")
	}
	roots["flow_view_list"] = object(map[string]any{"after": text(128), "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}, "search": text(256), "label": text(256), "visibility": map[string]any{"type": "string", "enum": []string{"", "private", "tenant"}}, "owner": text(1024), "sort": map[string]any{"type": "string", "enum": []string{"name", "created_at", "updated_at"}}, "tab": map[string]any{"type": "string", "enum": []string{"all", "favorites", "recents"}}})
	roots["flow_view_save"] = object(map[string]any{"id": id, "version": version, "definition": ref("FlowQueryViewDefinition")}, "definition")
	roots["flow_view_favorite"] = object(map[string]any{"id": id, "favorite": map[string]any{"type": "boolean"}}, "id", "favorite")
	return nativeMCPInputSchemas(components, roots)
}

// Resolve only reachable committed API definitions, with local recursive refs.
// All named native adapters share this resolver rather than copying grammars.
func nativeMCPInputSchemas(components map[string]json.RawMessage, roots map[string]any) (mcp.NativeFlowSchemas, error) {
	result := mcp.NativeFlowSchemas{}
	for name, root := range roots {
		definitions := map[string]any{}
		seen := map[string]bool{}
		var walk func(any) error
		walk = func(value any) error {
			switch node := value.(type) {
			case map[string]any:
				if value, ok := node["$ref"].(string); ok {
					if !strings.HasPrefix(value, "#/components/schemas/") {
						return errors.New("native schema has a nonlocal reference")
					}
					key := strings.TrimPrefix(value, "#/components/schemas/")
					node["$ref"] = "#/$defs/" + key
					if !seen[key] {
						seen[key] = true
						var child any
						if json.Unmarshal(components[key], &child) != nil {
							return errors.New("native schema reference is unavailable")
						}
						if err := walk(child); err != nil {
							return err
						}
						definitions[key] = child
					}
				}
				for key, child := range node {
					if key != "$ref" {
						if err := walk(child); err != nil {
							return err
						}
					}
				}
			case []any:
				for _, child := range node {
					if err := walk(child); err != nil {
						return err
					}
				}
			}
			return nil
		}
		// Clone roots because some small trusted property definitions are reused.
		raw, err := json.Marshal(root)
		if err != nil {
			return nil, err
		}
		var cloned map[string]any
		if err := json.Unmarshal(raw, &cloned); err != nil {
			return nil, err
		}
		if err := walk(cloned); err != nil {
			return nil, err
		}
		if len(definitions) > 0 {
			cloned["$defs"] = definitions
		}
		raw, err = json.Marshal(cloned)
		if err != nil {
			return nil, err
		}
		result[name] = raw
	}
	return result, nil
}
