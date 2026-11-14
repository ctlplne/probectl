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
	}
}
