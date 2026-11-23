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
	"github.com/ctlplne/probectl/internal/device"
)

type DeviceConfigPolicySource struct {
	ContextID      string `json:"context_id"`
	DeviceEntityID string `json:"device_entity_id"`
	AgentID        string `json:"agent_id"`
	SourceRef      string `json:"source_ref"`
}

// DevicePhysicalInventoryCommand identifies one original authoritative observation page.
type DevicePhysicalInventoryCommand struct {
	ContextID      string  `json:"context_id"`
	DeviceEntityID string  `json:"device_entity_id"`
	AgentID        string  `json:"agent_id"`
	SourceRef      string  `json:"source_ref"`
	ObservationID  string  `json:"observation_id,omitempty"`
	AfterIndex     *uint32 `json:"after_index,omitempty"`
}

// WithDevicePhysicalInventoryBackend installs the tenant-authorized native inventory read.
func WithDevicePhysicalInventoryBackend(schema json.RawMessage,
	read func(context.Context, *auth.Principal, DevicePhysicalInventoryCommand) (json.RawMessage, error)) Option {
	return func(s *Server) {
		if read == nil || !json.Valid(schema) {
			return
		}
		const name = "device_physical_inventory"
		tool := canonicalDeviceTool(s, name, "Read current physical components and cited local advisory flags from an owned device source.",
			"metrics.read", true, NativeFlowSchemas{name: schema}, read)
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}

type DeviceConfigPolicyUpdate struct {
	Binding          DeviceConfigPolicySource  `json:"binding"`
	ExpectedRevision string                    `json:"expected_revision"`
	Rules            []device.ConfigPolicyRule `json:"rules"`
}

type DeviceConfigPolicyRead struct {
	ID     string `json:"id"`
	Format string `json:"format,omitempty"`
}

type DeviceConfigPolicyBackend interface {
	DeviceConfigPolicy(context.Context, *auth.Principal, DeviceConfigPolicySource) (json.RawMessage, error)
	PublishDeviceConfigPolicy(context.Context, *auth.Principal, DeviceConfigPolicyUpdate) (json.RawMessage, error)
	DeviceConfigPolicyEvaluation(context.Context, *auth.Principal, DeviceConfigPolicyRead) (json.RawMessage, error)
}

func WithDeviceConfigPolicyBackend(backend DeviceConfigPolicyBackend, schemas NativeFlowSchemas) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tools := []Tool{
			canonicalDeviceTool(s, "device_config_policy", "Read the active configuration rule revision for an owned device source.",
				"metrics.read", true, schemas, backend.DeviceConfigPolicy),
			canonicalDeviceTool(s, "device_config_policy_publish", "Publish an explicit configuration policy revision for subsequent archives.",
				"metrics.write", false, schemas, backend.PublishDeviceConfigPolicy),
			canonicalDeviceTool(s, "device_config_policy_evaluation", "Read the retained evaluation and original redacted witnesses for an owned archive.",
				"metrics.read", true, schemas, backend.DeviceConfigPolicyEvaluation),
		}
		for _, tool := range tools {
			if !json.Valid(tool.InputSchema) {
				return
			}
		}
		s.nativeEnabled = true
		for _, tool := range tools {
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}

func canonicalDeviceTool[I any](s *Server, name, description, permission string, query bool, schemas NativeFlowSchemas,
	invoke func(context.Context, *auth.Principal, I) (json.RawMessage, error)) Tool {
	return Tool{Name: name, Description: description, Permission: permission, ExtraPermissions: []string{"ai.query", "entities.read"},
		Native: true, RequiresUser: true, Query: query, InputSchema: schemas[name],
		Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
			var input I
			if err := decodeBoundedNativeArgs(raw, &input, s.nativeRequestBytes()); err != nil {
				return nil, err
			}
			return invoke(ctx, actor, input)
		}}
}
