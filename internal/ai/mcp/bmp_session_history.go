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

type BMPSessionHistoryCommand struct {
	RouterID  string `json:"router_id"`
	ContextID string `json:"context_id"`
	Collector string `json:"collector_agent_id"`
	Source    string `json:"source_ref"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
	Limit     *int   `json:"limit,omitempty"`
	Statistic string `json:"statistic,omitempty"`
	AFI       string `json:"afi,omitempty"`
	SAFI      string `json:"safi,omitempty"`
	Minimum   string `json:"expected_min,omitempty"`
	Maximum   string `json:"expected_max,omitempty"`
}

type BMPSessionHistoryBackend interface {
	BMPSessionHistory(context.Context, *auth.Principal, BMPSessionHistoryCommand) (json.RawMessage, error)
}

func WithBMPSessionHistoryBackend(backend BMPSessionHistoryBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "bgp_session_history", Description: "Read retained BMP session evidence for one authorized router source. Neighbor addresses and router text are redacted. Repeat the source and filters when continuing.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "events.read", ExtraPermissions: []string{"entities.read", "ai.query"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command BMPSessionHistoryCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.RouterID == "" || command.ContextID == "" || command.Collector == "" || command.Source == "" {
					return nil, argErr("router, context, collector and source are required")
				}
				return backend.BMPSessionHistory(ctx, actor, command)
			},
		}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
