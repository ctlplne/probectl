// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tags"
)

var _ mcp.TagMutationBackend = mcpTagMutationBackend{}

type mcpTagMutationBackend struct{ server *Server }

func (b mcpTagMutationBackend) request(ctx context.Context, p *auth.Principal, action, path string) (*http.Request, error) {
	if b.server == nil || p == nil || p.TenantID == "" || strings.TrimSpace(p.UserID) == "" {
		return nil, apierror.Forbidden("an authenticated tenant user is required")
	}
	method := http.MethodPost
	switch action {
	case "read":
		method = http.MethodGet
	case "update":
		method = http.MethodPut
	case "delete":
		method = http.MethodDelete
	}
	return http.NewRequestWithContext(auth.WithPrincipal(ctx, p), method, path, nil)
}

func (b mcpTagMutationBackend) TagDefinitionWrite(ctx context.Context, p *auth.Principal, input mcp.TagDefinitionWriteInput) (mcp.TagMetadataWriteResult, error) {
	path := "/v1/tags"
	if input.ID != "" {
		path += "/" + url.PathEscape(input.ID)
	}
	r, err := b.request(ctx, p, input.Action, path)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	if input.Action == "delete" && !input.Confirmed {
		return mcp.TagMetadataWriteResult{}, apierror.BadRequest("explicit deletion confirmation is required")
	}
	key := ""
	if input.Input != nil {
		key = input.Input.Key
	}
	item, err := b.server.mutateTagDefinition(r, tagMutationAction(input.Action), input.ID, key)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	out := mcp.TagMetadataWriteResult{Action: input.Action, ID: item.ID}
	if input.Action != "delete" {
		out.Definition = &mcp.TagDefinitionResult{ID: item.ID, Key: item.Key}
	}
	return out, nil
}

func (b mcpTagMutationBackend) TagRuleWrite(ctx context.Context, p *auth.Principal, input mcp.TagRuleWriteInput) (mcp.TagMetadataWriteResult, error) {
	path := "/v1/entity-contexts/" + url.PathEscape(input.ContextID) + "/tag-rules"
	if input.ID != "" {
		path += "/" + url.PathEscape(input.ID)
	}
	r, err := b.request(ctx, p, input.Action, path)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	if input.Action == "delete" && !input.Confirmed {
		return mcp.TagMetadataWriteResult{}, apierror.BadRequest("explicit deletion confirmation is required")
	}
	fields := tagRuleInput{}
	if value := input.Input; value != nil {
		fields = tagRuleInput{TagID: value.TagID, TargetKind: value.TargetKind,
			Match: value.MatchKind, AddressSide: value.AddressSide, CIDR: value.CIDR,
			NamePattern: value.NamePattern, SNMPField: value.SNMPField,
			SNMPValue: value.SNMPValue, Value: value.Value, Priority: value.Priority}
	}
	item, err := b.server.mutateTagRule(r, tagMutationAction(input.Action), input.ContextID, input.ID, fields)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	out := mcp.TagMetadataWriteResult{Action: input.Action, ID: item.ID, ContextID: input.ContextID}
	if input.Action != "delete" {
		projected := mcpTagRule(item)
		out.Rule = &projected
	}
	return out, nil
}

func (b mcpTagMutationBackend) ManualTagAssignmentWrite(ctx context.Context, p *auth.Principal, input mcp.ManualTagAssignmentWriteInput) (mcp.TagMetadataWriteResult, error) {
	path := "/v1/entity-contexts/" + url.PathEscape(input.ContextID) + "/tag-assignments"
	if input.ID != "" {
		path += "/" + url.PathEscape(input.ID)
	}
	r, err := b.request(ctx, p, input.Action, path)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	if input.Action == "delete" && !input.Confirmed {
		return mcp.TagMetadataWriteResult{}, apierror.BadRequest("explicit deletion confirmation is required")
	}
	fields := manualTagAssignmentRequest{}
	if value := input.Input; value != nil {
		fields = manualTagAssignmentRequest{TagID: value.TagID, TargetKind: value.TargetKind,
			TargetID: value.TargetID, ExporterAgentID: value.ExporterAgentID,
			ExporterSourceRef: value.ExporterSourceRef, Value: value.Value}
	}
	item, err := b.server.mutateManualTagAssignment(r, tagMutationAction(input.Action), input.ContextID, input.ID, fields)
	if err != nil {
		return mcp.TagMetadataWriteResult{}, err
	}
	out := mcp.TagMetadataWriteResult{Action: input.Action, ID: item.ID, ContextID: input.ContextID}
	if input.Action != "delete" {
		projected := mcpTagAssignment(item)
		out.Assignment = &projected
	}
	return out, nil
}

func mcpTagRule(item tags.Rule) mcp.TagRuleResult {
	return mcp.TagRuleResult{ID: item.ID, TagID: item.TagID, TargetKind: item.TargetKind,
		MatchKind: item.Match, AddressSide: item.AddressSide, CIDR: item.CIDR,
		NamePattern: item.NamePattern, SNMPField: item.SNMPField,
		SNMPValue: item.SNMPValue, Value: item.Value, Priority: item.Priority}
}

// The nested input is the exact API schema. Action-specific envelopes add
// context/identifier and confirmation without exposing tenant/provenance fields.
func tagMutationToolSchemas() (map[string]json.RawMessage, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, 3)
	for _, target := range []struct {
		name, schema string
		context      bool
	}{
		{"tag_definition_write", "TagDefinitionInput", false},
		{"tag_rule_write", "TagRuleInput", true},
		{"tag_assignment_write", "ManualTagAssignmentInput", true},
	} {
		input := document.Components.Schemas[target.schema]
		if len(input) == 0 {
			return nil, errors.New("tag mutation API schema is unavailable")
		}
		properties := map[string]any{
			"action":    map[string]any{"type": "string", "enum": []string{"create", "update", "delete"}},
			"id":        map[string]any{"type": "string", "format": "uuid"},
			"confirmed": map[string]any{"type": "boolean", "const": true},
			"input":     input,
		}
		required := []string{"action"}
		if target.context {
			properties["context_id"] = map[string]any{"type": "string", "format": "uuid"}
			required = append(required, "context_id")
		}
		absent := func(field string) any { return map[string]any{"required": []string{field}} }
		variant := func(action string, need []string, forbidden any) any {
			return map[string]any{"properties": map[string]any{"action": map[string]any{"const": action}},
				"required": need, "not": forbidden}
		}
		encoded, err := json.Marshal(map[string]any{"type": "object", "additionalProperties": false,
			"properties": properties, "required": required,
			"oneOf": []any{
				variant("create", []string{"input"}, map[string]any{"anyOf": []any{absent("id"), absent("confirmed")}}),
				variant("update", []string{"id", "input"}, absent("confirmed")),
				variant("delete", []string{"id", "confirmed"}, absent("input")),
			}})
		if err != nil {
			return nil, err
		}
		out[target.name] = encoded
	}
	return out, nil
}
