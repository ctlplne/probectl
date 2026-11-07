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

	"github.com/ctlplne/probectl/internal/auth"
)

type BGPRoutingBindingCommand struct {
	ContextID        string           `json:"context_id"`
	CollectorAgentID string           `json:"collector_agent_id"`
	SourceRef        string           `json:"source_ref"`
	ExpectedEpoch    *string          `json:"expected_epoch,omitempty"`
	Bindings         *json.RawMessage `json:"bindings,omitempty"`
}

type BGPRoutingBindingBackend interface {
	BGPRoutingBindings(context.Context, *auth.Principal, bool, BGPRoutingBindingCommand) (json.RawMessage, error)
}

func decodeBGPRoutingBindingCommand(raw json.RawMessage, write bool, limit int) (BGPRoutingBindingCommand, error) {
	var input BGPRoutingBindingCommand
	if err := decodeBoundedNativeArgs(raw, &input, limit); err != nil {
		return BGPRoutingBindingCommand{}, err
	}
	if !validTagWriteID(input.ContextID) || strings.TrimSpace(input.CollectorAgentID) == "" || strings.TrimSpace(input.SourceRef) == "" {
		return BGPRoutingBindingCommand{}, argErr("owned context and complete source identity are required")
	}
	if !write && (input.ExpectedEpoch != nil || input.Bindings != nil) {
		return BGPRoutingBindingCommand{}, argErr("readback does not accept a replacement")
	}
	if write {
		if input.ExpectedEpoch == nil || input.Bindings == nil || !strings.HasPrefix(strings.TrimSpace(string(*input.Bindings)), "[") {
			return BGPRoutingBindingCommand{}, argErr("expected_epoch and a complete bindings array are required")
		}
		if *input.ExpectedEpoch != "" && !validTagWriteID(*input.ExpectedEpoch) {
			return BGPRoutingBindingCommand{}, argErr("expected_epoch must be a current server epoch")
		}
	}
	return input, nil
}

func WithBGPRoutingBindingBackend(backend BGPRoutingBindingBackend, schemas NativeFlowSchemas, inputBytes int) Option {
	return func(s *Server) {
		if backend == nil || inputBytes <= 0 || len(schemas["bgp_routing_bindings"]) == 0 || len(schemas["bgp_routing_bindings_replace"]) == 0 {
			return
		}
		s.nativeEnabled = true
		for _, name := range []string{"bgp_routing_bindings", "bgp_routing_bindings_replace"} {
			write := name == "bgp_routing_bindings_replace"
			permission := "entities.read"
			if write {
				permission = "agent.write"
			}
			s.tools[name] = Tool{Name: name, Permission: permission, RequiresUser: true, Native: true, InputSchema: append(json.RawMessage(nil), schemas[name]...),
				Description: "Read or atomically replace complete tenant-owned router-local source bindings using current context policy and exact epoch. A replacement retires prior routing generations; an empty bindings array withdraws all selectors. This configuration does not assert a live router or forwarding state. Existing MCP egress consent and redaction apply.",
				Invoke: func(ctx context.Context, principal *auth.Principal, raw json.RawMessage) (any, error) {
					input, err := decodeBGPRoutingBindingCommand(raw, write, min(inputBytes, s.nativeRequestBytes()))
					if err != nil {
						return nil, err
					}
					return backend.BGPRoutingBindings(ctx, principal, write, input)
				}}
			s.order = append(s.order, name)
		}
	}
}
