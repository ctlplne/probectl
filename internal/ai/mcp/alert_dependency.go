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
)

type AlertDependencyInput struct {
	RuleID string                       `json:"rule_id"`
	Input  *alert.DependencyPolicyInput `json:"input,omitempty"`
}

type AlertDependencyBackend interface {
	AlertDependencyGet(context.Context, *auth.Principal, string) (alert.DependencyPolicyState, error)
	AlertDependencySet(context.Context, *auth.Principal, AlertDependencyInput) (alert.DependencyPolicyState, error)
	AlertDependencyClear(context.Context, *auth.Principal, AlertTagFilterClearInput) (alert.DependencyPolicyState, error)
}

type AlertDependencyWorkflowBackend interface {
	AlertDependencyWorkflow(context.Context, *auth.Principal, string) (*alert.DependencyWorkflow, error)
}

func WithAlertDependencyBackend(backend AlertDependencyBackend, schemas map[string]json.RawMessage, inputBytes ...int) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, name := range []string{"alert_dependency_get", "alert_dependency_set", "alert_dependency_clear"} {
			if !json.Valid(schemas[name]) {
				return
			}
		}
		limit := s.nativeRequestBytes()
		if len(inputBytes) > 0 {
			limit = inputBytes[0]
		}
		if limit <= 0 {
			return
		}
		tools := []Tool{
			{Name: "alert_dependency_get", Permission: "alert.read", ExtraPermissions: []string{"topology.read", "entities.read"}, Description: "Read an owned rule's notification dependency configuration under your current source grants. Presence is not current hold evidence.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					RuleID string `json:"rule_id"`
				}
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) {
					return nil, argErr("a canonical owned alert rule ID is required")
				}
				return dependencyNativeResult(backend.AlertDependencyGet(ctx, p, input.RuleID))
			}},
			{Name: "alert_dependency_set", Permission: "alert.write", ExtraPermissions: []string{"topology.read", "entities.read", "test.read", "metrics.read"}, Description: "Configure an owned rule's context, finite source freshness and optional complete directed canonical graph with exact same-vantage ICMP sources. Stores only your read capability ceiling; collection and detection remain active.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertDependencyInput
				if err := decodeBoundedNativeArgs(raw, &input, min(limit, s.nativeRequestBytes())); err != nil || !validAlertTagRuleID(input.RuleID) || input.Input == nil {
					return nil, argErr("an owned rule and complete dependency configuration are required")
				}
				normalized, err := alert.NormalizeDependencyPolicyInput(*input.Input)
				if err != nil {
					return nil, argErr("an exact routing context and finite positive source freshness are required")
				}
				input.Input = &normalized
				return dependencyNativeResult(backend.AlertDependencySet(ctx, p, input))
			}},
			{Name: "alert_dependency_clear", Permission: "alert.write", Description: "Explicitly clear notification dependency configuration without disabling collection or detection. Previous source reads are not required.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertTagFilterClearInput
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) || !input.Confirmed {
					return nil, argErr("an owned rule and explicit clear confirmation are required")
				}
				return dependencyNativeResult(backend.AlertDependencyClear(ctx, p, input))
			}},
		}
		if workflow, ok := backend.(AlertDependencyWorkflowBackend); ok && json.Valid(schemas["alert_dependency_workflow"]) {
			tools = append(tools, Tool{Name: "alert_dependency_workflow", Permission: "alert.read", ExtraPermissions: []string{"topology.read", "entities.read", "test.read", "metrics.read", "incident.read"}, Description: "Explain an active series' notification dependency using current source and reader/owner authority. A stored marker is never current hold evidence.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					Fingerprint string `json:"fingerprint"`
				}
				if err := decodeNativeArgs(raw, &input); err != nil || input.Fingerprint == "" {
					return nil, argErr("an owned active alert fingerprint is required")
				}
				return dependencyWorkflowNativeResult(workflow.AlertDependencyWorkflow(ctx, p, input.Fingerprint))
			}})
		}
		for _, tool := range tools {
			// The domain backend owns query admission; a second lease here
			// would deadlock a tenant configured for one concurrent query.
			tool.RequiresUser, tool.Native, tool.Query = true, true, true
			tool.InputSchema = append(json.RawMessage(nil), schemas[tool.Name]...)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
