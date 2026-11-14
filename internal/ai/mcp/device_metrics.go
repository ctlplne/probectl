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

type DeviceMetricsCommand struct {
	Device string `json:"device,omitempty"`
	Metric string `json:"metric,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
}

type DeviceMetricsBackend interface {
	DeviceMetrics(context.Context, *auth.Principal, DeviceMetricsCommand) (json.RawMessage, error)
}

func WithDeviceMetricsBackend(backend DeviceMetricsBackend, schema json.RawMessage) Option {
	return func(s *Server) {
		if backend == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "device_metrics", Description: "Read latest tenant-scoped device, interface and component samples under configured resource admission. Optical component levels and channel zero stay distinct; missing levels are not zero and component names do not prove canonical ports. Device text retains full redaction.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "metrics.read", ExtraPermissions: []string{"ai.query"}, Native: true, RequiresUser: true, Query: true,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command DeviceMetricsCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if command.Limit != nil && *command.Limit < 1 {
					return nil, argErr("limit must be positive when supplied")
				}
				return backend.DeviceMetrics(ctx, actor, command)
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
