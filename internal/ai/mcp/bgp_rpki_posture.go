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

type BGPRPKIPostureCommand struct {
	ID          string  `json:"id"`
	ContextID   string  `json:"context_id"`
	PrefixID    string  `json:"prefix_id"`
	IntendedASN *uint32 `json:"intended_asn,omitempty"`
}

type BGPRPKIPostureBackend interface {
	BGPRPKIPosture(context.Context, *auth.Principal, BGPRPKIPostureCommand) (json.RawMessage, error)
}

func WithBGPRPKIPostureBackend(backend BGPRPKIPostureBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "bgp_rpki_posture", Description: "Read current RPKI validation and retained original validation for an owned monitored prefix. Exact ROA suggestions are for operator review.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "events.read", ExtraPermissions: []string{"ai.query", "entities.read"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command BGPRPKIPostureCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.ID == "" || command.ContextID == "" || command.PrefixID == "" || command.IntendedASN != nil && (*command.IntendedASN == 0 || *command.IntendedASN == 23456) {
					return nil, argErr("monitor, owned routing context and owned prefix are required")
				}
				return backend.BGPRPKIPosture(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
