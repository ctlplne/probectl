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

const RoutingTransferToolName = "flow_routing_transfer_estimate"

func WithRoutingTransferEstimate(schema json.RawMessage, read func(context.Context, *auth.Principal, json.RawMessage) (json.RawMessage, error)) Option {
	return func(s *Server) {
		if read == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{
			Name: RoutingTransferToolName, InputSchema: append(json.RawMessage(nil), schema...),
			Description: "Estimate charges and headroom for moving one exact prefix between owned upstream handoffs. Optionally compare paired active probes against performance and charge limits. Requires original evidence and returns a read-only policy preview.",
			Permission:  "flow.agreements.read", ExtraPermissions: []string{"topology.read", "flow.read", "entities.read", "metrics.read", "events.read"},
			Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				if len(raw) == 0 || len(raw) > s.nativeRequestBytes() {
					return nil, argErr("complete routing transfer input must fit resource admission")
				}
				return read(ctx, p, raw)
			},
		}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
