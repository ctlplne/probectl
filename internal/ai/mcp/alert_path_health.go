// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
)

type AlertPathHealthInput struct {
	RuleID string                       `json:"rule_id"`
	Input  *alert.PathHealthSourceInput `json:"input,omitempty"`
}

type AlertPathHealthBackend interface {
	AlertPathHealthCreate(context.Context, *auth.Principal, alert.PathHealthRuleInput) (alert.Rule, error)
	AlertPathHealthGet(context.Context, *auth.Principal, string) (alert.PathHealthSourceState, error)
	AlertPathHealthSet(context.Context, *auth.Principal, AlertPathHealthInput) (alert.PathHealthSourceState, error)
	AlertPathHealthClear(context.Context, *auth.Principal, AlertTagFilterClearInput) (alert.PathHealthSourceState, error)
}

// Only the closed server vocabulary receives structural escaping. Names,
// notification destinations and all other free text retain full redaction.
type nativeAlertPathHealthMetric string

func (metric nativeAlertPathHealthMetric) MarshalJSON() ([]byte, error) {
	if !alert.IsPathHealthErrorMetric(string(metric)) {
		return nil, errors.New("invalid server path-error metric")
	}
	raw, err := json.Marshal(string(metric))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), ".", `\u002e`)), nil
}

type nativeAlertPathHealthInput struct {
	TestID          NativeRoleUUID              `json:"test_id"`
	InterfaceID     NativeRoleUUID              `json:"interface_id"`
	Metric          nativeAlertPathHealthMetric `json:"metric"`
	LookbackSeconds int64                       `json:"lookback_seconds,omitempty"`
	PollGapSeconds  int64                       `json:"poll_gap_seconds,omitempty"`
}

type nativeAlertPathHealthState struct {
	RuleID        NativeRoleUUID              `json:"rule_id"`
	RuleUpdatedAt time.Time                   `json:"rule_updated_at"`
	Configured    bool                        `json:"configured"`
	Source        *nativeAlertPathHealthInput `json:"source,omitempty"`
}

func pathHealthSourceResult(state alert.PathHealthSourceState, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	out := nativeAlertPathHealthState{RuleID: NativeRoleUUID(state.RuleID), RuleUpdatedAt: state.RuleUpdatedAt, Configured: state.Configured}
	if state.Source != nil {
		source := state.Source
		out.Source = &nativeAlertPathHealthInput{NativeRoleUUID(source.TestID), NativeRoleUUID(source.InterfaceID), nativeAlertPathHealthMetric(source.Metric), source.LookbackSeconds, source.PollGapSeconds}
	}
	return out, nil
}

// The domain service owns its complete original-counter query lease, including
// final source/authority checks. The normal transport still owns full redaction
// and exact originating-credential refresh on HTTPS and persistent stdio.
func WithAlertPathHealthBackend(backend AlertPathHealthBackend, schemas map[string]json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, name := range []string{"alert_path_health_create", "alert_path_health_get", "alert_path_health_set", "alert_path_health_clear"} {
			if !json.Valid(schemas[name]) {
				return
			}
		}
		tools := []Tool{
			{Name: "alert_path_health_create", Permission: "alert.write", ExtraPermissions: []string{"ai.query", "test.read", "entities.read", "metrics.read"}, Description: "Create an original-counter error-climb alert on a current owned path and canonical interface. Missing or reset evidence holds the existing episode; it never becomes a healthy zero.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input alert.PathHealthRuleInput
				if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil {
					return nil, argErr("a name and complete owned path-health source are required")
				}
				source, err := alert.NormalizePathHealthSource(input.PathHealthSource)
				if err != nil {
					return nil, argErr("an owned test, canonical interface and original error counter are required")
				}
				input.PathHealthSource = source
				rule, err := backend.AlertPathHealthCreate(ctx, p, input)
				if err != nil {
					return nil, err
				}
				return struct {
					alert.Rule
					ID       NativeRoleUUID `json:"id"`
					TenantID NativeRoleUUID `json:"tenant_id"`
				}{rule, NativeRoleUUID(rule.ID), NativeRoleUUID(rule.TenantID)}, nil
			}},
			{Name: "alert_path_health_get", Permission: "alert.read", ExtraPermissions: []string{"ai.query", "test.read", "entities.read", "metrics.read"}, Description: "Read a path-error alert source after a complete current source preview under your grants. Stored credential ceilings and baseline values are never returned.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					RuleID string `json:"rule_id"`
				}
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) {
					return nil, argErr("a canonical owned alert rule ID is required")
				}
				return pathHealthSourceResult(backend.AlertPathHealthGet(ctx, p, input.RuleID))
			}},
			{Name: "alert_path_health_set", Permission: "alert.write", ExtraPermissions: []string{"ai.query", "test.read", "entities.read", "metrics.read"}, Description: "Bind a current owned test, canonical interface and original error counter after complete admission and current-authority checks.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertPathHealthInput
				if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil || !validAlertTagRuleID(input.RuleID) || input.Input == nil {
					return nil, argErr("an owned rule ID and complete path-health source are required")
				}
				source, err := alert.NormalizePathHealthSource(*input.Input)
				if err != nil {
					return nil, argErr("an owned test, canonical interface and original error counter are required")
				}
				input.Input = &source
				return pathHealthSourceResult(backend.AlertPathHealthSet(ctx, p, input))
			}},
			{Name: "alert_path_health_clear", Permission: "alert.write", Description: "Explicitly clear an owned path-error source and disable evaluation. Reads no previous source criteria.", Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				var input AlertTagFilterClearInput
				if err := decodeNativeArgs(raw, &input); err != nil || !validAlertTagRuleID(input.RuleID) || !input.Confirmed {
					return nil, argErr("an owned rule ID and explicit clear confirmation are required")
				}
				return pathHealthSourceResult(backend.AlertPathHealthClear(ctx, p, input))
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
