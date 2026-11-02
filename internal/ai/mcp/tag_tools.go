// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/auth"
)

// MCP tag tools expose bounded, named projections. The shared MCP egress gate
// redacts each response after tenant-first and resource ABAC authorization.
type TagDefinitionResult struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type TagDefinitionListResult struct {
	Items []TagDefinitionResult `json:"items"`
}

type TagContextListInput struct {
	ContextID string `json:"context_id"`
	Cursor    string `json:"cursor"`
	Limit     int    `json:"limit"`
}

type TagRuleResult struct {
	ID          string `json:"id"`
	TagID       string `json:"tag_id"`
	TargetKind  string `json:"target_kind"`
	MatchKind   string `json:"match_kind"`
	AddressSide string `json:"address_side,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	NamePattern string `json:"name_pattern,omitempty"`
	SNMPField   string `json:"snmp_field,omitempty"`
	SNMPValue   string `json:"snmp_value,omitempty"`
	Value       string `json:"value"`
	Priority    int    `json:"priority"`
}

type TagRuleListResult struct {
	ContextID  string          `json:"context_id"`
	Items      []TagRuleResult `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type TagAssignmentResult struct {
	ID         string `json:"id"`
	TagID      string `json:"tag_id"`
	TargetKind string `json:"target_kind"`
	TargetID   string `json:"target_id,omitempty"`
	Value      string `json:"value"`
	Source     string `json:"source"`
}

type TagAssignmentListResult struct {
	ContextID  string                `json:"context_id"`
	Items      []TagAssignmentResult `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type TagBackend interface {
	TagDefinitionList(context.Context, *auth.Principal) (TagDefinitionListResult, error)
	TagRuleList(context.Context, *auth.Principal, TagContextListInput) (TagRuleListResult, error)
	TagAssignmentList(context.Context, *auth.Principal, TagContextListInput) (TagAssignmentListResult, error)
}

func WithTagBackend(backend TagBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, tool := range buildTagTools(backend) {
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}

func buildTagTools(backend TagBackend) []Tool {
	contextSchema := json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string","format":"uuid"},"cursor":{"type":"string","format":"uuid"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id"],"additionalProperties":false}`)
	listContext := func(name, description string,
		invoke func(context.Context, *auth.Principal, TagContextListInput) (any, error)) Tool {
		return Tool{Name: name, Description: description, Permission: "tags.read",
			InputSchema: contextSchema, RequiresUser: true,
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input TagContextListInput
				if err := decodeNativeArgs(raw, &input); err != nil {
					return nil, argErr("invalid tag context arguments")
				}
				return invoke(ctx, p, input)
			}}
	}
	return []Tool{
		{Name: "tag_definition_list", Description: "List the caller tenant's bounded tag keys.",
			Permission: "tags.read", RequiresUser: true,
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct{}
				if err := decodeNativeArgs(raw, &input); err != nil {
					return nil, argErr("invalid tag arguments")
				}
				return backend.TagDefinitionList(ctx, p)
			}},
		listContext("tag_rule_list", "Page tag rules in an owned routing context.",
			func(ctx context.Context, p *auth.Principal, input TagContextListInput) (any, error) {
				return backend.TagRuleList(ctx, p, input)
			}),
		listContext("tag_assignment_list", "Page assigned tag values in an owned routing context; source references are omitted.",
			func(ctx context.Context, p *auth.Principal, input TagContextListInput) (any, error) {
				return backend.TagAssignmentList(ctx, p, input)
			}),
	}
}
