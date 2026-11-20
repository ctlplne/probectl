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

type BGPASPathHistoryCommand struct {
	ID      string `json:"id"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Source  string `json:"source,omitempty"`
	Vantage string `json:"vantage,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
	Limit   *int   `json:"limit,omitempty"`
}

type BGPASPathHistoryBackend interface {
	BGPASPathHistory(context.Context, *auth.Principal, BGPASPathHistoryCommand) (json.RawMessage, error)
}

func WithBGPASPathHistoryBackend(backend BGPASPathHistoryBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "bgp_as_path_history", Description: "Read one monitored prefix's retained AS paths and changes by public collector or authorized BMP view. The read uses only local history and current caller permissions.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "events.read", ExtraPermissions: []string{"ai.query"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command BGPASPathHistoryCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.ID == "" {
					return nil, argErr("monitor id is required")
				}
				return backend.BGPASPathHistory(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
