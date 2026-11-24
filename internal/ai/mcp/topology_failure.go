// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/topology"
)

type TopologyFailureBackend func(context.Context, *auth.Principal, topology.FailureSimulationRequest) (json.RawMessage, error)

func WithTopologyFailureBackend(backend TopologyFailureBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		const name = "topology_whatif_traffic"
		s.nativeEnabled = true
		s.tools[name] = Tool{
			Name: name, Permission: ai.PermTopologyRead,
			ExtraPermissions: []string{"ai.query", "flow.read", ai.PermEntitiesRead, ai.PermMetricsRead, ai.PermEventsRead},
			RequiresUser:     true, Native: true, Query: true, InputSchema: schema,
			Description: "Preview one failed node or physical link using read-only access to the tenant's retained flow, routing and counter observations. Returns directional offered load and evidence coverage.",
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var input topology.FailureSimulationRequest
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), 64<<10)); err != nil {
					return nil, err
				}
				return backend(ctx, actor, input)
			},
		}
		s.order = append(s.order, name)
	}
}
