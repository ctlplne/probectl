// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
)

type PathHealthCommand struct {
	TestID        string `json:"test_id"`
	HealthFrom    string `json:"health_from,omitempty"`
	HealthTo      string `json:"health_to,omitempty"`
	HealthPollGap string `json:"health_poll_gap,omitempty"`
	HealthMaxBPS  string `json:"health_max_bps,omitempty"`
}

type PathHealthBackend interface {
	PathInterfaceHealth(context.Context, *auth.Principal, PathHealthCommand) (json.RawMessage, error)
}

type PathHealthExplanationCommand struct {
	TestID        string `json:"test_id"`
	HealthFrom    string `json:"health_from,omitempty"`
	HealthTo      string `json:"health_to,omitempty"`
	HealthPollGap string `json:"health_poll_gap,omitempty"`
	HealthMaxBPS  string `json:"health_max_bps,omitempty"`
	Question      string `json:"question"`
}

type PathHealthExplanationBackend interface {
	ExplainPathInterfaceHealth(context.Context, *auth.Principal, PathHealthExplanationCommand) (json.RawMessage, error)
}

// The shared backend owns complete query admission. The normal native
// publication boundary retains consent, full redaction and exact live
// credential/policy refresh for HTTPS and authenticated persistent stdio.
func WithPathHealthBackend(backend PathHealthBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "path_interface_health", Description: "Preview original directional interface counters for the latest owned path's uniquely resolved current ports. Exact words, original receipts, speed and explicit rate assumptions are retained; missing, reset and ambiguous observations remain unavailable. Physical routed/SNMP qualification is still pending.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "test.read", ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read"}, Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command PathHealthCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if !validTagWriteID(command.TestID) {
					return nil, argErr("an owned test UUID is required")
				}
				return backend.PathInterfaceHealth(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
		if explanation, ok := backend.(PathHealthExplanationBackend); ok {
			registerPathHealthExplanation(s, explanation, schema)
		}
	}
}

func registerPathHealthExplanation(s *Server, backend PathHealthExplanationBackend, healthSchema json.RawMessage) {
	var schema struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	if err := json.Unmarshal(healthSchema, &schema); err != nil || schema.Properties == nil {
		return
	}
	schema.Properties["question"] = json.RawMessage(`{"type":"string","minLength":1,"maxLength":2000}`)
	schema.Required = []string{"test_id", "question"}
	encoded, err := json.Marshal(schema)
	if err != nil {
		return
	}
	tool := Tool{Name: "path_interface_health_explain", Description: "Explain the latest owned path using complete original polled interface observations and exact citations. Preview: current identities, explicit counter assumptions and missing observations are retained; correlation does not establish the cause of path loss.",
		InputSchema: encoded, Permission: "test.read", ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read"}, Native: true, RequiresUser: true, Query: true,
		Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
			var command PathHealthExplanationCommand
			if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
				return nil, err
			}
			command.Question = strings.TrimSpace(command.Question)
			if !validTagWriteID(command.TestID) || command.Question == "" || len(command.Question) > 2000 {
				return nil, argErr("an owned test UUID and a question of 1–2000 characters are required")
			}
			return backend.ExplainPathInterfaceHealth(ctx, actor, command)
		}}
	s.tools[tool.Name] = tool
	s.order = append(s.order, tool.Name)
}
