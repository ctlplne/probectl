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

const InstantTestStatusToolName = "instant_test_status"

func WithInstantTestStatus(read func(context.Context, *auth.Principal, json.RawMessage) (json.RawMessage, error)) Option {
	return func(s *Server) {
		if read == nil {
			return
		}
		tool := Tool{
			Name:        InstantTestStatusToolName,
			Description: "Read the current agent outcomes and metrics of one authorized on-demand test run.",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["run_id"],"properties":{"run_id":{"type":"string","format":"uuid"}}}`),
			Permission:  "test.read", ExtraPermissions: []string{"agent.read", "metrics.read"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				if len(raw) == 0 || len(raw) > s.nativeRequestBytes() {
					return nil, argErr("a complete instant test run identity is required")
				}
				return read(ctx, p, raw)
			},
		}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
