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

type IncidentVerdictBackend interface {
	IncidentVerdict(context.Context, *auth.Principal, string, incident.VerdictInput) (json.RawMessage, error)
}

type IncidentVerdictCommand struct {
	IncidentID string    `json:"incident_id"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
}

func WithIncidentVerdictBackend(backend IncidentVerdictBackend, schemas NativeFlowSchemas, admit NativeFlowAdmission) Option {
	return func(s *Server) {
		schema := schemas["incident_verdict"]
		if backend == nil || admit == nil || !json.Valid(schema) {
			return
		}
		tool := Tool{Name: "incident_verdict", Description: "Preview cited fault-domain hypotheses for an incident's explicit observation window. Original local interface states and independently corroborated verified primary HTTPS errors supply initial rules; carrier and wider-internet coverage remain unavailable. Thin or conflicting evidence remains unknown. Complete domain and lab qualification is pending.", InputSchema: append(json.RawMessage(nil), schema...), Permission: "incident.read", ExtraPermissions: []string{"entities.read", "metrics.read", "events.read", "test.read"}, Native: true, RequiresUser: true, Query: true, Admit: admit,
			Invoke: func(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (any, error) {
				var command IncidentVerdictCommand
				if err := decodeBoundedNativeArgs(raw, &command, s.nativeRequestBytes()); err != nil {
					return nil, err
				}
				if !validTagWriteID(command.IncidentID) || command.From.IsZero() || command.To.IsZero() || !command.To.After(command.From) {
					return nil, argErr("owned incident ID and explicit increasing from/to are required")
				}
				return backend.IncidentVerdict(ctx, actor, command.IncidentID, incident.VerdictInput{From: command.From, To: command.To})
			}}
		s.nativeEnabled = true
		s.tools[tool.Name] = tool
		s.order = append(s.order, tool.Name)
	}
}
