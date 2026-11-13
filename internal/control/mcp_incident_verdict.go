// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

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

// Only this fixed server contract receives structural encoding. Dots in an
// unescaped version otherwise resemble a hostname to the ordinary PII masker.
type nativeIncidentVerdictContract string

type nativeIncidentPathRound string

func (value nativeIncidentPathRound) MarshalJSON() ([]byte, error) {
	if _, err := (incident.VerdictCitation{SourceKind: "control_plane_path", PathRoundID: string(value), AgentID: "control_plane"}).SourceReference(); err != nil {
		return nil, err
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, character := range string(value) {
		if character >= '0' && character <= '9' {
			out.WriteString(`\u003`)
		}
		out.WriteRune(character)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func (value nativeIncidentVerdictContract) MarshalJSON() ([]byte, error) {
	if value != "probectl.incident-verdict.v1" {
		return nil, errors.New("invalid server incident verdict contract")
	}
	raw, err := json.Marshal(string(value))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), ".", `\u002e`)), nil
}

// Only server-selected canonical UUIDs and computed document digests get
// structural encoding. Agent labels and all other text retain full redaction.
func marshalNativeIncidentVerdict(value incident.FaultVerdict) (json.RawMessage, error) {
	type routingReference struct {
		incident.VerdictRoutingReference
		ViewID       mcp.NativeRoleUUID     `json:"view_id"`
		GenerationID mcp.NativeRoleUUID     `json:"generation_id"`
		Sequence     mcp.NativeRoleRevision `json:"sequence"`
	}
	projectRouting := func(input *incident.VerdictRoutingReference) *routingReference {
		if input == nil {
			return nil
		}
		return &routingReference{*input, mcp.NativeRoleUUID(input.ViewID), mcp.NativeRoleUUID(input.GenerationID), mcp.NativeRoleRevision(input.Sequence)}
	}

	type citation struct {
		incident.VerdictCitation
		Routing            *routingReference       `json:"routing,omitempty"`
		ContextID          mcp.NativeRoleUUID      `json:"context_id"`
		EntityID           mcp.NativeRoleUUID      `json:"entity_id"`
		EvidenceID         mcp.NativeRoleUUID      `json:"evidence_id,omitempty"`
		PathRoundID        nativeIncidentPathRound `json:"path_round_id,omitempty"`
		HandoffInterfaceID mcp.NativeRoleUUID      `json:"handoff_interface_id,omitempty"`
		Digest             mcp.NativeRoleDigest    `json:"digest"`
	}
	project := func(items []incident.VerdictCitation) []citation {
		out := make([]citation, 0, len(items))
		for _, item := range items {
			out = append(out, citation{VerdictCitation: item, Routing: projectRouting(item.Routing), ContextID: mcp.NativeRoleUUID(item.ContextID), EntityID: mcp.NativeRoleUUID(item.EntityID), EvidenceID: mcp.NativeRoleUUID(item.EvidenceID), PathRoundID: nativeIncidentPathRound(item.PathRoundID), HandoffInterfaceID: mcp.NativeRoleUUID(item.HandoffInterfaceID), Digest: mcp.NativeRoleDigest(item.Digest)})
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
		ContractVersion nativeIncidentVerdictContract `json:"contract_version"`
		IncidentID      mcp.NativeRoleUUID            `json:"incident_id"`
		Hypotheses      []hypothesis                  `json:"hypotheses"`
	}{FaultVerdict: value, ContractVersion: nativeIncidentVerdictContract(value.ContractVersion), IncidentID: mcp.NativeRoleUUID(value.IncidentID), Hypotheses: []hypothesis{}}
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
