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
	"github.com/ctlplne/probectl/internal/entity"
)

type InterfaceRoleCommand struct {
	ContextID        string
	InterfaceID      string
	ExpectedID       string
	ExpectedRevision string
	Definition       *entity.InterfaceRolePolicyDefinition
	Role             entity.InterfaceRole
	Confirmed        bool
}

type InterfaceRoleBackend interface {
	InterfaceRoleConfiguration(context.Context, *auth.Principal, string, InterfaceRoleCommand) (json.RawMessage, error)
}

type interfaceRoleReadInput struct {
	ContextID   string `json:"context_id"`
	InterfaceID string `json:"interface_id,omitempty"`
}
type interfaceRolePolicyWriteInput struct {
	ContextID        string                                `json:"context_id"`
	ExpectedID       string                                `json:"expected_id"`
	ExpectedRevision string                                `json:"expected_revision"`
	Definition       *entity.InterfaceRolePolicyDefinition `json:"definition"`
}
type interfaceRoleOverrideWriteInput struct {
	ContextID        string               `json:"context_id"`
	InterfaceID      string               `json:"interface_id"`
	ExpectedID       string               `json:"expected_id"`
	ExpectedRevision string               `json:"expected_revision"`
	Role             entity.InterfaceRole `json:"role"`
}
type interfaceRoleResetInput struct {
	ContextID        string `json:"context_id"`
	InterfaceID      string `json:"interface_id"`
	ExpectedID       string `json:"expected_id"`
	ExpectedRevision string `json:"expected_revision"`
	Confirmed        bool   `json:"confirmed"`
}

func decodeInterfaceRoleCommand(raw json.RawMessage, name string, limit int) (InterfaceRoleCommand, error) {
	var command InterfaceRoleCommand
	var err error
	switch name {
	case "interface_role_policy_set":
		var input interfaceRolePolicyWriteInput
		err = decodeBoundedNativeArgs(raw, &input, limit)
		command = InterfaceRoleCommand{ContextID: input.ContextID, ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Definition: input.Definition}
		if err == nil && input.Definition == nil {
			err = argErr("complete role policy is required")
		}
	case "interface_role_override_set":
		var input interfaceRoleOverrideWriteInput
		err = decodeBoundedNativeArgs(raw, &input, limit)
		command = InterfaceRoleCommand{ContextID: input.ContextID, InterfaceID: input.InterfaceID, ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Role: input.Role}
	case "interface_role_override_reset":
		var input interfaceRoleResetInput
		err = decodeBoundedNativeArgs(raw, &input, limit)
		command = InterfaceRoleCommand{ContextID: input.ContextID, InterfaceID: input.InterfaceID, ExpectedID: input.ExpectedID, ExpectedRevision: input.ExpectedRevision, Confirmed: input.Confirmed}
		if err == nil && !input.Confirmed {
			err = argErr("explicit override reset confirmation is required")
		}
	case "interface_role_policy":
		var input struct {
			ContextID string `json:"context_id"`
		}
		err = decodeBoundedNativeArgs(raw, &input, limit)
		command = InterfaceRoleCommand{ContextID: input.ContextID}
	default:
		var input interfaceRoleReadInput
		err = decodeBoundedNativeArgs(raw, &input, limit)
		command = InterfaceRoleCommand{ContextID: input.ContextID, InterfaceID: input.InterfaceID}
		if name == "interface_role_policy" && input.InterfaceID != "" {
			err = argErr("policy does not select an interface")
		}
	}
	if err != nil {
		return InterfaceRoleCommand{}, err
	}
	if !validTagWriteID(command.ContextID) || ((name != "interface_role_policy" && name != "interface_role_policy_set") && !validTagWriteID(command.InterfaceID)) {
		return InterfaceRoleCommand{}, argErr("owned context/interface identity is required")
	}
	return command, nil
}

func WithInterfaceRoleBackend(backend InterfaceRoleBackend, schemas NativeFlowSchemas, inputBytes int) Option {
	return func(s *Server) {
		names := []string{"interface_role_explain", "interface_role_policy", "interface_role_policy_set", "interface_role_override", "interface_role_override_set", "interface_role_override_reset"}
		if backend == nil || inputBytes <= 0 {
			return
		}
		for _, name := range names {
			if len(schemas[name]) == 0 {
				return
			}
		}
		s.nativeEnabled = true
		for _, name := range names {
			write := name != "interface_role_explain" && name != "interface_role_policy" && name != "interface_role_override"
			permission := "entities.read"
			if write {
				permission = "agent.write"
			}
			description := "Read or explicitly replace owned interface-role configuration with current context authorization and exact incarnation/revision. Ordered rules are complete; overrides persist until a confirmed reset."
			if name == "interface_role_explain" {
				description = "Explain the current owned interface role and every contributing source. Requires current entities.read, metrics.read and events.read. Missing or ambiguous automatic evidence remains other; an owned override wins. No BGP session-health claim."
			}
			tool := Tool{Name: name, Permission: permission, RequiresUser: write, Native: true, InputSchema: append(json.RawMessage(nil), schemas[name]...), Description: description, Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
				command, err := decodeInterfaceRoleCommand(raw, name, min(inputBytes, s.nativeRequestBytes()))
				if err != nil {
					return nil, err
				}
				return backend.InterfaceRoleConfiguration(ctx, p, name, command)
			}}
			if name == "interface_role_explain" {
				tool.ExtraPermissions = []string{"metrics.read", "events.read"}
				tool.RequiresUser = true
			}
			s.tools[name] = tool
			s.order = append(s.order, name)
		}
	}
}
