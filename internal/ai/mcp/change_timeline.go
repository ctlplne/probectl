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

type ChangeTimelineCommand struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

type ChangeTimelineBackend interface {
	ChangeTimeline(context.Context, *auth.Principal, ChangeTimelineCommand) (json.RawMessage, error)
}

func WithChangeTimelineBackend(backend ChangeTimelineBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "changes_list", Description: "Page original authenticated owned-router, signed webhook and content-free configuration changes. Follow next_cursor until empty; current tenant/user/source grants are checked on every page and before publication. BGP-selected routes do not prove forwarding state. Config contents need their separate archive read.", InputSchema: append(json.RawMessage(nil), schema...), Permission: "change.read", ExtraPermissions: []string{"ai.query"}, Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command ChangeTimelineCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.Limit != nil && *command.Limit < 1 {
					return nil, argErr("limit must be positive")
				}
				return backend.ChangeTimeline(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
