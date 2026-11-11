// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type AlertQuerySourceInput struct {
	RuleID string                  `json:"rule_id"`
	Input  *alert.QuerySourceInput `json:"input,omitempty"`
}

type AlertQueryGroupInput struct {
	RuleID string `json:"rule_id"`
	Group  string `json:"group"`
}

type AlertQueryBackend interface {
	AlertQueryGroupGet(context.Context, *auth.Principal, AlertQueryGroupInput) (alert.QueryGroupInspection, error)
	AlertQueryCreate(context.Context, *auth.Principal, alert.QueryRuleInput) (alert.Rule, error)
	AlertQuerySourceGet(context.Context, *auth.Principal, string) (alert.QuerySourceState, error)
	AlertQuerySourceSet(context.Context, *auth.Principal, AlertQuerySourceInput) (alert.QuerySourceState, error)
	AlertQuerySourceClear(context.Context, *auth.Principal, AlertTagFilterClearInput) (alert.QuerySourceState, error)
}

// The domain backend owns the shared Explorer admission through publication;
// taking a second query lease here would deadlock a one-query tenant policy.
func WithAlertQueryBackend(backend AlertQueryBackend, schemas map[string]json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, name := range []string{"alert_query_create", "alert_query_group_get", "alert_query_source_get", "alert_query_source_set", "alert_query_source_clear"} {
			if !json.Valid(schemas[name]) {
				return
			}
		}
		tools := []Tool{
			{Name: "alert_query_group_get", Permission: "alert.read", ExtraPermissions: []string{"ai.query", "flow.read"}, Description: "Inspect a current saved-query group with your own source grants. Returns exact dimensions/value or explicit absence; never a historical firing receipt and never advances baseline, schedule or delivery.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertQueryGroupInput
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) || !alert.ValidQueryGroupKey(input.Group) {
					return nil, argErr("an owned rule and canonical opaque group handle are required")
				}
				return backend.AlertQueryGroupGet(ctx, p, input)
			}},
			{Name: "alert_query_create", Permission: "alert.write", ExtraPermissions: []string{"ai.query", "flow.read"}, Description: "Create a saved-query alert with complete source admission, exact decimal conditions and current owner grants. Optional delivery uses the normal configured channels.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input alert.QueryRuleInput
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), flow.MaxPlanGrammarBytes)); err != nil {
					return nil, argErr("a name and complete saved-query alert input are required")
				}
				normalized, err := alert.NormalizeQuerySourceInput(input.QuerySource)
				if err != nil {
					return nil, argErr("an exact saved revision, schedule and grouped condition are required")
				}
				input.QuerySource = normalized
				return backend.AlertQueryCreate(ctx, p, input)
			}},
			{Name: "alert_query_source_get", Permission: "alert.read", ExtraPermissions: []string{"ai.query", "flow.read"}, Description: "Read an exact saved-query alert source under current source grants, without stored credential ceilings or baseline values.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					RuleID string `json:"rule_id"`
				}
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) {
					return nil, argErr("a canonical owned alert rule ID is required")
				}
				return backend.AlertQuerySourceGet(ctx, p, input.RuleID)
			}},
			{Name: "alert_query_source_set", Permission: "alert.write", ExtraPermissions: []string{"ai.query", "flow.read"}, Description: "Bind an exact saved Explorer revision and exact decimal threshold or complete new-group condition. Full source cost and current grants are checked before persistence.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertQuerySourceInput
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), flow.MaxPlanGrammarBytes)); err != nil || !validAlertTagRuleID(input.RuleID) || input.Input == nil {
					return nil, argErr("an owned rule ID and complete saved-query source are required")
				}
				normalized, err := alert.NormalizeQuerySourceInput(*input.Input)
				if err != nil {
					return nil, argErr("an exact saved revision, schedule and grouped condition are required")
				}
				input.Input = &normalized
				return backend.AlertQuerySourceSet(ctx, p, input)
			}},
			{Name: "alert_query_source_clear", Permission: "alert.write", Description: "Explicitly clear an owned rule's saved-query source and baseline and disable evaluation. Reads no previous criteria.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertTagFilterClearInput
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) || !input.Confirmed {
					return nil, argErr("an owned rule ID and explicit clear confirmation are required")
				}
				return backend.AlertQuerySourceClear(ctx, p, input)
			}},
		}
		for _, tool := range tools {
			tool.RequiresUser, tool.Native, tool.Query = true, true, true
			tool.InputSchema = append(json.RawMessage(nil), schemas[tool.Name]...)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
