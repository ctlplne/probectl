// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type mcpInterfaceRoleBackend struct{ server *Server }

func (b mcpInterfaceRoleBackend) InterfaceRoleConfiguration(ctx context.Context, p *auth.Principal, name string, input mcp.InterfaceRoleCommand) (json.RawMessage, error) {
	if b.server == nil || p == nil || p.TenantID == "" {
		return nil, apierror.Unauthorized("tenant identity is required")
	}
	path := "/v1/entity-contexts/" + url.PathEscape(input.ContextID)
	method := http.MethodGet
	var value any
	switch name {
	case "interface_role_explain":
		path += "/interfaces/" + url.PathEscape(input.InterfaceID) + "/role"
	case "interface_role_policy":
		path += "/interface-role-policy"
	case "interface_role_policy_set":
		path += "/interface-role-policy"
		method = http.MethodPut
		value = interfaceRolePolicyInput{ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Definition: input.Definition}
	case "interface_role_override":
		path += "/interfaces/" + url.PathEscape(input.InterfaceID) + "/role-override"
	case "interface_role_override_set":
		path += "/interfaces/" + url.PathEscape(input.InterfaceID) + "/role-override"
		method = http.MethodPut
		value = interfaceRoleOverrideInput{ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Role: input.Role}
	case "interface_role_override_reset":
		path += "/interfaces/" + url.PathEscape(input.InterfaceID) + "/role-override"
		method = http.MethodDelete
		value = interfaceRoleResetInput{ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Confirmed: input.Confirmed}
	default:
		return nil, apierror.BadRequest("unknown interface role command")
	}
	if method != http.MethodGet && strings.TrimSpace(p.UserID) == "" {
		return nil, apierror.Forbidden("an authenticated tenant user is required")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, p), method, path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("context_id", input.ContextID)
	r.SetPathValue("id", input.InterfaceID)
	if method != http.MethodGet && b.server.cluster != nil {
		if ok, _ := b.server.cluster.WriterUsableNow(ctx); !ok {
			return nil, apierror.Unavailable("writer unavailable")
		}
	}
	if name == "interface_role_explain" {
		body, err := b.server.interfaceRoleExplanation(r)
		if err != nil {
			return nil, err
		}
		return marshalRoleMCPExplanation(body)
	}
	if name == "interface_role_policy" || name == "interface_role_policy_set" {
		body, err := b.server.interfaceRolePolicy(r)
		if err != nil {
			return nil, err
		}
		return marshalRoleMCPPolicy(body)
	}
	result, err := b.server.interfaceRoleOverride(r)
	if err == nil && method == http.MethodDelete {
		return json.RawMessage(`{"reset":true}`), nil
	}
	if err != nil {
		return nil, err
	}
	return marshalRoleMCPOverride(result)
}

func interfaceRoleToolSchemas() (mcp.NativeFlowSchemas, error) {
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	roots := map[string]any{}
	for _, item := range []struct {
		name, schema   string
		write, subject bool
	}{
		{"interface_role_explain", "", false, true}, {"interface_role_policy", "", false, false}, {"interface_role_policy_set", "InterfaceRolePolicyInput", true, false},
		{"interface_role_override", "", false, true}, {"interface_role_override_set", "InterfaceRoleOverrideInput", true, true}, {"interface_role_override_reset", "InterfaceRoleOverrideResetInput", true, true},
	} {
		root := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}, "required": []any{}}
		if item.write {
			if json.Unmarshal(doc.Components.Schemas[item.schema], &root) != nil {
				return nil, errors.New("role input API schema unavailable")
			}
		}
		properties := root["properties"].(map[string]any)
		required := root["required"].([]any)
		properties["context_id"] = map[string]any{"type": "string", "format": "uuid"}
		required = append(required, "context_id")
		if item.subject {
			properties["interface_id"] = map[string]any{"type": "string", "format": "uuid"}
			required = append(required, "interface_id")
		}
		root["required"] = required
		roots[item.name] = root
	}
	return nativeMCPInputSchemas(doc.Components.Schemas, roots)
}

func interfaceRoleToolOption(s *Server) (mcp.Option, error) {
	schemas, err := interfaceRoleToolSchemas()
	if err != nil {
		return nil, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if budget.Validate() != nil {
		return nil, errors.New("role operation admission unavailable")
	}
	return mcp.WithInterfaceRoleBackend(mcpInterfaceRoleBackend{server: s}, schemas, int(interfaceRoleBodyBytes(budget))), nil
}
