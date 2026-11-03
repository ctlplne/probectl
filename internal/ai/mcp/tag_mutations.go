// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tags"
)

type TagDefinitionFields struct {
	Key string `json:"key"`
}

type TagRuleFields struct {
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

// These fields name only an owned target. Source/provenance and tenant are
// selected by the command, never supplied by a tool caller.
type ManualTagAssignmentFields struct {
	TagID             string `json:"tag_id"`
	TargetKind        string `json:"target_kind"`
	TargetID          string `json:"target_id,omitempty"`
	ExporterAgentID   string `json:"exporter_agent_id,omitempty"`
	ExporterSourceRef string `json:"exporter_source_ref,omitempty"`
	Value             string `json:"value"`
}

type TagDefinitionWriteInput struct {
	Action    string               `json:"action"`
	ID        string               `json:"id,omitempty"`
	Confirmed bool                 `json:"confirmed,omitempty"`
	Input     *TagDefinitionFields `json:"input,omitempty"`
}

type TagRuleWriteInput struct {
	Action    string         `json:"action"`
	ContextID string         `json:"context_id"`
	ID        string         `json:"id,omitempty"`
	Confirmed bool           `json:"confirmed,omitempty"`
	Input     *TagRuleFields `json:"input,omitempty"`
}

type ManualTagAssignmentWriteInput struct {
	Action    string                     `json:"action"`
	ContextID string                     `json:"context_id"`
	ID        string                     `json:"id,omitempty"`
	Confirmed bool                       `json:"confirmed,omitempty"`
	Input     *ManualTagAssignmentFields `json:"input,omitempty"`
}

type TagMetadataWriteResult struct {
	Action     string               `json:"action"`
	ID         string               `json:"id"`
	ContextID  string               `json:"context_id,omitempty"`
	Definition *TagDefinitionResult `json:"definition,omitempty"`
	Rule       *TagRuleResult       `json:"rule,omitempty"`
	Assignment *TagAssignmentResult `json:"assignment,omitempty"`
}

type TagMutationBackend interface {
	TagDefinitionWrite(context.Context, *auth.Principal, TagDefinitionWriteInput) (TagMetadataWriteResult, error)
	TagRuleWrite(context.Context, *auth.Principal, TagRuleWriteInput) (TagMetadataWriteResult, error)
	ManualTagAssignmentWrite(context.Context, *auth.Principal, ManualTagAssignmentWriteInput) (TagMetadataWriteResult, error)
}

func validTagWriteID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil
}

func validTagWriteEnvelope(raw json.RawMessage, action, id string, confirmed, hasInput bool) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	_, idPresent := fields["id"]
	_, inputPresent := fields["input"]
	_, confirmationPresent := fields["confirmed"]
	switch action {
	case "create":
		return !idPresent && !confirmationPresent && hasInput
	case "update":
		return validTagWriteID(id) && !confirmationPresent && hasInput
	case "delete":
		return validTagWriteID(id) && confirmed && !inputPresent
	default:
		return false
	}
}

// Each tool has one bounded, typed command family. The schemas are generated
// from the API inputs; no arbitrary route or untyped mutation is exposed.
func WithTagMutationBackend(backend TagMutationBackend, schemas map[string]json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, name := range []string{"tag_definition_write", "tag_rule_write", "tag_assignment_write"} {
			if len(schemas[name]) == 0 {
				return // missing contract keeps all writes unavailable
			}
		}
		tools := []Tool{
			{Name: "tag_definition_write", Permission: "tags.write", RequiresUser: true,
				Description: "Create, rename or explicitly confirm deletion of an owned tag key. Deletion also removes its rules and assignments; the change and audit commit together.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input TagDefinitionWriteInput
					if err := decodeBoundedNativeArgs(raw, &input, tags.MaxValueInputBytes); err != nil ||
						!validTagWriteEnvelope(raw, input.Action, input.ID, input.Confirmed, input.Input != nil) {
						return nil, argErr("invalid tag definition action, input or deletion confirmation")
					}
					return backend.TagDefinitionWrite(ctx, p, input)
				}},
			{Name: "tag_rule_write", Permission: "tags.write", RequiresUser: true,
				Description: "Create, update or explicitly confirm deletion of a rule in an owned routing context, with current authorization and atomic audit.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input TagRuleWriteInput
					if err := decodeBoundedNativeArgs(raw, &input, tags.MaxValueInputBytes); err != nil ||
						!validTagWriteID(input.ContextID) || !validTagWriteEnvelope(raw, input.Action, input.ID, input.Confirmed, input.Input != nil) {
						return nil, argErr("invalid tag rule action, context, input or deletion confirmation")
					}
					return backend.TagRuleWrite(ctx, p, input)
				}},
			{Name: "tag_assignment_write", Permission: "tags.write", RequiresUser: true,
				Description: "Create, update or explicitly confirm deletion of a manual assignment on an owned target. Imported assignments and their provenance cannot be changed through this tool.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input ManualTagAssignmentWriteInput
					if err := decodeBoundedNativeArgs(raw, &input, tags.MaxValueInputBytes); err != nil ||
						!validTagWriteID(input.ContextID) || !validTagWriteEnvelope(raw, input.Action, input.ID, input.Confirmed, input.Input != nil) {
						return nil, argErr("invalid manual tag action, context, input or deletion confirmation")
					}
					return backend.ManualTagAssignmentWrite(ctx, p, input)
				}},
		}
		for _, tool := range tools {
			tool.InputSchema = append(json.RawMessage(nil), schemas[tool.Name]...)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
