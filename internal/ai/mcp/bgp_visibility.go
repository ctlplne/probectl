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

type BGPVisibilityCommand struct {
	ID     string `json:"id"`
	Before string `json:"before,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
}

type BGPVisibilityBackend interface {
	BGPVisibility(context.Context, *auth.Principal, BGPVisibilityCommand) (json.RawMessage, error)
}

func WithBGPVisibilityBackend(backend BGPVisibilityBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "bgp_visibility_history", Description: "Read measured public collector coverage and original origin counts for an existing tenant monitor. An unavailable point omits counts. This operation reads the local history only.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "events.read", ExtraPermissions: []string{"ai.query"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command BGPVisibilityCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.ID == "" {
					return nil, argErr("monitor id is required")
				}
				return backend.BGPVisibility(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
