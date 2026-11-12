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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
)

type IncidentImpactBackend interface {
	IncidentImpact(context.Context, *auth.Principal, string, incident.ImpactInput) (json.RawMessage, error)
}

type IncidentImpactCommand struct {
	IncidentID     string    `json:"incident_id"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	DataSeries     string    `json:"dataseries,omitempty"`
	CustomerTagKey string    `json:"customer_tag_key,omitempty"`
}

func WithIncidentImpactBackend(backend IncidentImpactBackend, schemas NativeFlowSchemas, admit NativeFlowAdmission) Option {
	return func(s *Server) {
		schema := schemas["incident_impact"]
		if backend == nil || admit == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "incident_impact", Description: "Preview observed incident traffic against the same window one week earlier, with original-capture and customer-prefix citations. Missing coverage stays unavailable. Test/SLO attribution and physical-flow qualification remain pending.",
			InputSchema: append(json.RawMessage(nil), schema...), Permission: "incident.read", ExtraPermissions: []string{"flow.read", "entities.read", "metrics.read", "events.read"}, Native: true, RequiresUser: true, Query: true, Admit: admit,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command IncidentImpactCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if !validTagWriteID(command.IncidentID) || command.From.IsZero() || command.To.IsZero() || !command.To.After(command.From) {
					return nil, argErr("owned incident ID and explicit increasing from/to are required")
				}
				return backend.IncidentImpact(ctx, actor, command.IncidentID, incident.ImpactInput{From: command.From, To: command.To, DataSeries: command.DataSeries, CustomerTagKey: command.CustomerTagKey})
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
