// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
)

type mcpIncidentVerdictBackend struct{ server *Server }

func (b mcpIncidentVerdictBackend) IncidentVerdict(ctx context.Context, actor *auth.Principal, id string, input incident.VerdictInput) (json.RawMessage, error) {
	if b.server == nil {
		return nil, apierror.Unavailable("incident verdict service is unavailable")
	}
	result, err := b.server.queryIncidentVerdict(ctx, actor, id, input)
	if err != nil {
		return nil, err
	}
	return marshalNativeIncidentVerdict(result)
}

// Only server-selected canonical UUIDs and computed document digests get
// structural encoding. Agent labels and all other text retain full redaction.
func marshalNativeIncidentVerdict(value incident.FaultVerdict) (json.RawMessage, error) {
	type citation struct {
		incident.VerdictCitation
		ContextID  mcp.NativeRoleUUID   `json:"context_id"`
		EntityID   mcp.NativeRoleUUID   `json:"entity_id"`
		EvidenceID mcp.NativeRoleUUID   `json:"evidence_id"`
		Digest     mcp.NativeRoleDigest `json:"digest"`
	}
	project := func(items []incident.VerdictCitation) []citation {
		out := make([]citation, 0, len(items))
		for _, item := range items {
			out = append(out, citation{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.EntityID), mcp.NativeRoleUUID(item.EvidenceID), mcp.NativeRoleDigest(item.Digest)})
		}
		return out
	}
	type hypothesis struct {
		incident.VerdictHypothesis
		For     []citation `json:"for"`
		Against []citation `json:"against"`
	}
	out := struct {
		incident.FaultVerdict
		IncidentID mcp.NativeRoleUUID `json:"incident_id"`
		Hypotheses []hypothesis       `json:"hypotheses"`
	}{FaultVerdict: value, IncidentID: mcp.NativeRoleUUID(value.IncidentID), Hypotheses: []hypothesis{}}
	for _, item := range value.Hypotheses {
		out.Hypotheses = append(out.Hypotheses, hypothesis{item, project(item.For), project(item.Against)})
	}
	return json.Marshal(out)
}

func incidentVerdictToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	schemas, err := nativeMCPInputSchemas(document.Components.Schemas, map[string]any{"incident_verdict": map[string]any{"$ref": "#/components/schemas/IncidentVerdictCommand"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithIncidentVerdictBackend(mcpIncidentVerdictBackend{server}, schemas, server.beginIncidentVerdictQuery), nil
}
