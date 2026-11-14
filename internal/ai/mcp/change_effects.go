// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

type ChangeEffectsCommand struct {
	ChangeID   string    `json:"change_id"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	DataSeries string    `json:"dataseries,omitempty"`
}

type ChangeEffectsBackend interface {
	ChangeEffects(context.Context, *auth.Principal, ChangeEffectsCommand) (json.RawMessage, error)
}

func WithChangeEffectsBackend(backend ChangeEffectsBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "change_effects", Description: "Compare complete original measurements before and after an exact change. Current tenant/user/source grants, original credentials, revocation and erasure state are rechecked before publication. Missing RTTs or counters are unknown; observed differences do not prove causation.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "change.read", ExtraPermissions: []string{"flow.read", "entities.read", "metrics.read", "events.read", "test.read", "ai.query"}, Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command ChangeEffectsCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				id := strings.TrimPrefix(command.ChangeID, "device-config:")
				if !validTagWriteID(id) || command.From.IsZero() || !command.To.After(command.From) {
					return nil, argErr("exact original change ID and explicit increasing from/to are required")
				}
				return backend.ChangeEffects(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
