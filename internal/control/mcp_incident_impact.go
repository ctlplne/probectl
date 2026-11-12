// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
)

type mcpIncidentImpactBackend struct{ server *Server }

func (b mcpIncidentImpactBackend) IncidentImpact(ctx context.Context, actor *auth.Principal, id string, input incident.ImpactInput) (json.RawMessage, error) {
	if b.server == nil {
		return nil, apierror.Unavailable("incident impact service is unavailable")
	}
	result, err := b.server.incidentImpact(ctx, actor, id, input)
	if err != nil {
		return nil, err
	}
	return marshalNativeIncidentImpact(result)
}

type nativeIncidentChange string

func (value nativeIncidentChange) MarshalJSON() ([]byte, error) {
	text := string(value)
	encoded, err := mcp.NativePeeringCounter(strings.TrimPrefix(text, "-")).MarshalJSON()
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(text, "-") {
		return append([]byte{'"', '-'}, encoded[1:]...), nil
	}
	return encoded, nil
}

func marshalNativeIncidentImpact(value incident.ImpactResponse) (json.RawMessage, error) {
	type counters struct {
		RawBytes      mcp.NativePeeringCounter `json:"raw_bytes"`
		RawPackets    mcp.NativePeeringCounter `json:"raw_packets"`
		ScaledBytes   mcp.NativePeeringCounter `json:"scaled_bytes"`
		ScaledPackets mcp.NativePeeringCounter `json:"scaled_packets"`
	}
	projectCounters := func(input *incident.ImpactCounters) *counters {
		if input == nil {
			return nil
		}
		return &counters{mcp.NativePeeringCounter(input.RawBytes), mcp.NativePeeringCounter(input.RawPackets), mcp.NativePeeringCounter(input.ScaledBytes), mcp.NativePeeringCounter(input.ScaledPackets)}
	}
	ids := func(input []string) []mcp.NativeRoleUUID {
		out := make([]mcp.NativeRoleUUID, len(input))
		for i, id := range input {
			out[i] = mcp.NativeRoleUUID(id)
		}
		return out
	}
	type capture struct {
		incident.ImpactCaptureCitation
		ContextID mcp.NativeRoleUUID `json:"context_id"`
		RouterID  mcp.NativeRoleUUID `json:"router_id"`
	}
	type period struct {
		incident.ImpactPeriod
		Totals   *counters `json:"observed_totals,omitempty"`
		Captures []capture `json:"captures"`
	}
	projectPeriod := func(input incident.ImpactPeriod) period {
		out := period{input, projectCounters(input.ObservedTotals), make([]capture, 0, len(input.Captures))}
		for _, item := range input.Captures {
			out.Captures = append(out.Captures, capture{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.RouterID)})
		}
		return out
	}
	type member struct {
		incident.ImpactMember
		ContextID mcp.NativeRoleUUID   `json:"context_id"`
		EntityID  mcp.NativeRoleUUID   `json:"entity_id"`
		SignalIDs []mcp.NativeRoleUUID `json:"signal_ids"`
	}
	type customer struct {
		incident.ImpactCustomer
		ContextID mcp.NativeRoleUUID   `json:"context_id"`
		PrefixIDs []mcp.NativeRoleUUID `json:"prefix_ids"`
		TestIDs   []mcp.NativeRoleUUID `json:"test_ids"`
		SLOIDs    []mcp.NativeRoleUUID `json:"slo_ids"`
		Current   *counters            `json:"current_observed_totals,omitempty"`
		Previous  *counters            `json:"previous_observed_totals,omitempty"`
	}
	out := struct {
		incident.ImpactResponse
		IncidentID mcp.NativeRoleUUID   `json:"incident_id"`
		Current    period               `json:"current"`
		Previous   period               `json:"previous"`
		Members    []member             `json:"members"`
		Unresolved []mcp.NativeRoleUUID `json:"unresolved_signal_ids"`
		Customers  []customer           `json:"customers"`
		Change     nativeIncidentChange `json:"observed_scaled_byte_change,omitempty"`
	}{
		ImpactResponse: value, IncidentID: mcp.NativeRoleUUID(value.IncidentID), Current: projectPeriod(value.Current), Previous: projectPeriod(value.Previous), Members: []member{}, Unresolved: ids(value.UnresolvedSignalIDs), Customers: []customer{}, Change: nativeIncidentChange(value.ObservedByteChange)}
	for _, item := range value.Members {
		out.Members = append(out.Members, member{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.EntityID), ids(item.SignalIDs)})
	}
	for _, item := range value.Customers {
		out.Customers = append(out.Customers, customer{item, mcp.NativeRoleUUID(item.ContextID), ids(item.PrefixIDs), ids(item.TestIDs), ids(item.SLOIDs), projectCounters(item.Current), projectCounters(item.Previous)})
	}
	return json.Marshal(out)
}

func incidentImpactToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	schemas, err := nativeMCPInputSchemas(document.Components.Schemas, map[string]any{"incident_impact": map[string]any{"$ref": "#/components/schemas/IncidentImpactCommand"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithIncidentImpactBackend(mcpIncidentImpactBackend{server}, schemas, server.beginIncidentImpactQuery), nil
}
