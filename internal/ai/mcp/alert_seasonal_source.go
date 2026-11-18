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

type AlertSeasonalSourceBackend interface {
	AlertSeasonalFlowCreate(context.Context, *auth.Principal, string, alert.SeasonalBaselineInput) (alert.SeasonalSourceState, error)
	AlertSeasonalSourceGet(context.Context, *auth.Principal, string) (alert.SeasonalSourceState, error)
	AlertSeasonalSourceSet(context.Context, *auth.Principal, string, *alert.SeasonalBaselineInput) (alert.SeasonalSourceState, error)
}

type seasonalToolInput struct {
	RuleID    string                       `json:"rule_id"`
	Input     *alert.SeasonalBaselineInput `json:"input,omitempty"`
	Confirmed bool                         `json:"confirmed,omitempty"`
}

func WithAlertSeasonalSourceBackend(backend AlertSeasonalSourceBackend, schemas map[string]json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tools := []Tool{
			{Name: "alert_seasonal_flow_create", Permission: "alert.write", ExtraPermissions: []string{"ai.query", "flow.read"}, Description: "Create a weekly baseline on one current owned Explorer view and exact flow measure."},
			{Name: "alert_seasonal_source_get", Permission: "alert.read", ExtraPermissions: []string{"ai.query"}, Description: "Inspect the current local weekly baseline and its holiday calendar for an owned alert rule."},
			{Name: "alert_seasonal_source_set", Permission: "alert.write", ExtraPermissions: []string{"ai.query"}, Description: "Set the timezone, holidays and minimum change of an owned rule and bind its current metric, test or saved flow source."},
			{Name: "alert_seasonal_source_clear", Permission: "alert.write", ExtraPermissions: []string{"ai.query"}, Description: "Confirm clearing the weekly source and disabling its rule."},
		}
		for _, tool := range tools {
			if !json.Valid(schemas[tool.Name]) {
				return
			}
		}
		for _, tool := range tools {
			tool.RequiresUser, tool.Native, tool.Query = true, true, true
			tool.InputSchema = append(json.RawMessage(nil), schemas[tool.Name]...)
			tool.Invoke = s.invokeSeasonalSource(backend, tool.Name)
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}

func (s *Server) invokeSeasonalSource(backend AlertSeasonalSourceBackend, name string) func(context.Context, *auth.Principal, json.RawMessage) (any, error) {
	if name == "alert_seasonal_flow_create" {
		return s.invokeSeasonalFlowCreate(backend)
	}
	return func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
		var input seasonalToolInput
		if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil || !validAlertTagRuleID(input.RuleID) {
			return nil, argErr("an owned rule ID is required")
		}
		state, err := runSeasonalSourceTool(ctx, actor, backend, name, input)
		if err != nil {
			return nil, err
		}
		return projectSeasonalSourceState(state), nil
	}
}

func (s *Server) invokeSeasonalFlowCreate(backend AlertSeasonalSourceBackend) func(context.Context, *auth.Principal, json.RawMessage) (any, error) {
	return func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
		var input struct {
			Name   string                      `json:"name"`
			Source alert.SeasonalBaselineInput `json:"seasonal_source"`
		}
		if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil || input.Source.Flow == nil {
			return nil, argErr("a name and an owned saved flow source are required")
		}
		state, err := backend.AlertSeasonalFlowCreate(ctx, actor, input.Name, input.Source)
		if err != nil {
			return nil, err
		}
		return projectSeasonalSourceState(state), nil
	}
}

type nativeSeasonalFlowInput struct {
	ViewID      NativeRoleUUID     `json:"view_id"`
	ViewVersion NativeRoleRevision `json:"view_version"`
	Measure     string             `json:"measure"`
}

type nativeSeasonalInput struct {
	alert.SeasonalBaselineInput
	TestID NativeRoleUUID           `json:"test_id,omitempty"`
	Flow   *nativeSeasonalFlowInput `json:"flow,omitempty"`
}

func projectSeasonalSourceState(state alert.SeasonalSourceState) any {
	var source *nativeSeasonalInput
	if state.Source != nil {
		source = &nativeSeasonalInput{SeasonalBaselineInput: *state.Source, TestID: NativeRoleUUID(state.Source.TestID)}
		if view := state.Source.Flow; view != nil {
			source.Flow = &nativeSeasonalFlowInput{NativeRoleUUID(view.ViewID), NativeRoleRevision(view.ViewVersion), view.Measure}
		}
	}
	return struct {
		alert.SeasonalSourceState
		RuleID NativeRoleUUID       `json:"rule_id"`
		Source *nativeSeasonalInput `json:"source,omitempty"`
	}{state, NativeRoleUUID(state.RuleID), source}
}

func runSeasonalSourceTool(ctx context.Context, actor *auth.Principal, backend AlertSeasonalSourceBackend, name string, input seasonalToolInput) (alert.SeasonalSourceState, error) {
	switch name {
	case "alert_seasonal_source_get":
		if input.Input == nil && !input.Confirmed {
			return backend.AlertSeasonalSourceGet(ctx, actor, input.RuleID)
		}
	case "alert_seasonal_source_set":
		if input.Input != nil && !input.Confirmed {
			return backend.AlertSeasonalSourceSet(ctx, actor, input.RuleID, input.Input)
		}
	case "alert_seasonal_source_clear":
		if input.Input == nil && input.Confirmed {
			return backend.AlertSeasonalSourceSet(ctx, actor, input.RuleID, nil)
		}
	}
	return alert.SeasonalSourceState{}, argErr("provide settings to set a source or confirm to clear it")
}
