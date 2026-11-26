// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/topology"
)

type CloudTopologyBackend func(context.Context, *auth.Principal, time.Time) (topology.Viz, error)

func WithCloudTopologyBackend(read CloudTopologyBackend, admit NativeFlowAdmission) Option {
	return func(s *Server) {
		if read == nil {
			return
		}
		const name = "topology_cloud"
		s.nativeEnabled = true
		s.tools[name] = Tool{
			Name: name, Permission: ai.PermTopologyRead, ExtraPermissions: []string{permAIQuery},
			RequiresUser: true, Native: true, Query: true, Admit: admit,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"at":{"type":"string","format":"date-time"}},"additionalProperties":false}`),
			Description: "Preview. Read AWS, Azure and Google Cloud inventory nodes and relationships for the current tenant. Returns the latest complete snapshot from each source when fresh at the optional RFC 3339 time. These are configuration observations.",
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					At time.Time `json:"at,omitempty"`
				}
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), 8<<10)); err != nil {
					return nil, err
				}
				graph, err := read(ctx, actor, input.At)
				if err != nil {
					return nil, err
				}
				return struct {
					topology.Viz
					LatestOnly bool `json:"cloud_latest_only"`
				}{Viz: graph, LatestOnly: true}, nil
			},
		}
		s.order = append(s.order, name)
	}
}
