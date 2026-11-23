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

type KubernetesTopologyBackend func(context.Context, *auth.Principal, string, time.Time) (topology.Viz, error)

func WithKubernetesTopologyBackend(backend KubernetesTopologyBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		const name = "topology_kubernetes"
		s.nativeEnabled = true
		s.tools[name] = Tool{
			Name: name, Permission: ai.PermTopologyRead, ExtraPermissions: []string{ai.PermEntitiesRead},
			RequiresUser: true, Native: true, Query: true,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string","format":"uuid"},"at":{"type":"string","format":"date-time"}},"required":["context_id"],"additionalProperties":false}`),
			Description: "Read witnessed Kubernetes objects, controller ownership, and Service backends in one owned routing context. An explicit time requires evidence covering that instant. Otherwise each object carries the time of its last completed observation.",
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var input struct {
					ContextID string    `json:"context_id"`
					At        time.Time `json:"at,omitempty"`
				}
				if err := decodeBoundedNativeArgs(raw, &input, min(s.nativeRequestBytes(), 8<<10)); err != nil {
					return nil, err
				}
				if !validTagWriteID(input.ContextID) {
					return nil, argErr("an owned routing context is required")
				}
				return backend(ctx, actor, input.ContextID, input.At)
			},
		}
		s.order = append(s.order, name)
	}
}
