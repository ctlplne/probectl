// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type AlertTagFilterInput struct {
	RuleID string                `json:"rule_id"`
	Input  *alert.TagFilterInput `json:"input,omitempty"`
}

type AlertTagFilterClearInput struct {
	RuleID    string `json:"rule_id"`
	Confirmed bool   `json:"confirmed"`
}

type AlertTagBackend interface {
	AlertTagAdmission(context.Context, *auth.Principal) (func(), error)
	AlertTagFilterGet(context.Context, *auth.Principal, string) (alert.TagFilterState, error)
	AlertTagFilterSet(context.Context, *auth.Principal, AlertTagFilterInput) (alert.TagFilterState, error)
	AlertTagFilterClear(context.Context, *auth.Principal, AlertTagFilterClearInput) (alert.TagFilterState, error)
}

func validAlertTagRuleID(id string) bool {
	parsed, err := gouuid.Parse(id)
	return err == nil && parsed != gouuid.Nil && parsed.String() == id
}

// Inputs are resolved from committed API schemas. Dispatch retains live source
// grants, authenticated users, native whole-result costs and the egress audit.
func WithAlertTagBackend(backend AlertTagBackend, schemas map[string]json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, name := range []string{"alert_tag_filter_get", "alert_tag_filter_set", "alert_tag_filter_clear"} {
			if len(schemas[name]) == 0 {
				return
			}
		}
		tools := []Tool{
			{Name: "alert_tag_filter_get", Permission: "alert.read", ExtraPermissions: []string{"tags.read", "test.read", "metrics.read"},
				Description: "Read complete current alert test-tag criteria and exact binding revision under current user/source grants; no channel secrets are returned.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input struct {
						RuleID string `json:"rule_id"`
					}
					if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) {
						return nil, argErr("a canonical owned alert rule ID is required")
					}
					return backend.AlertTagFilterGet(ctx, p, input.RuleID)
				}},
			{Name: "alert_tag_filter_set", Permission: "alert.write", ExtraPermissions: []string{"tags.read", "test.read", "metrics.read"},
				Description: "Set complete nested current test-tag criteria on an owned metric alert; the current user becomes the owner and the data/domain audit commit together.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input AlertTagFilterInput
					if err := decodeBoundedNativeArgs(raw, &input, flow.MaxPlanGrammarBytes); err != nil || !validAlertTagRuleID(input.RuleID) || input.Input == nil {
						return nil, argErr("an owned rule ID and complete alert tag input are required")
					}
					return backend.AlertTagFilterSet(ctx, p, input)
				}},
			{Name: "alert_tag_filter_clear", Permission: "alert.write",
				Description: "Explicitly confirm removal of an owned alert's tag criteria. Requires current alert.write; returns no previous metadata and preserves other rule settings.",
				Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
					var input AlertTagFilterClearInput
					if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) || !input.Confirmed {
						return nil, argErr("an owned rule ID and explicit clear confirmation are required")
					}
					return backend.AlertTagFilterClear(ctx, p, input)
				}},
		}
		for _, tool := range tools {
			tool.RequiresUser, tool.Native, tool.Query = true, true, true
			tool.Admit = backend.AlertTagAdmission
			tool.InputSchema = append(json.RawMessage(nil), schemas[tool.Name]...)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
