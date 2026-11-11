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
	"github.com/ctlplne/probectl/internal/flow"
)

type mcpPeeringBackend struct{ server *Server }

func (b mcpPeeringBackend) PeeringEstimate(ctx context.Context, p *auth.Principal, input flow.PeeringEstimateInput) (json.RawMessage, error) {
	if b.server == nil {
		return nil, apierror.Unavailable("peering service is unavailable")
	}
	result, err := b.server.runPeeringEstimate(ctx, p, input)
	if err != nil {
		return nil, err
	}
	return marshalNativePeeringResponse(result)
}

type nativePeeringRate struct {
	flow.PeeringRateEstimate
	Bytes       mcp.NativePeeringCounter `json:"selected_interval_bytes"`
	Numerator   mcp.NativePeeringCounter `json:"bits_per_second_numerator"`
	Denominator mcp.NativePeeringCounter `json:"bits_per_second_denominator"`
}

func nativePeeringRateValue(value flow.PeeringRateEstimate) nativePeeringRate {
	return nativePeeringRate{value, mcp.NativePeeringCounter(value.SelectedIntervalBytes), mcp.NativePeeringCounter(value.BitsPerSecondNumerator), mcp.NativePeeringCounter(value.BitsPerSecondDenominator)}
}

func marshalNativePeeringResponse(value flow.PeeringEstimateResponse) (json.RawMessage, error) {
	type target struct {
		flow.PeeringEstimateTarget
		ContextID   mcp.NativeRoleUUID `json:"context_id"`
		InterfaceID mcp.NativeRoleUUID `json:"interface_id"`
		RouterID    mcp.NativeRoleUUID `json:"router_id,omitempty"`
		IXID        any                `json:"ix_id"`
		LANID       any                `json:"ix_lan_id"`
	}
	type transit struct {
		InterfaceID mcp.NativeRoleUUID `json:"interface_id"`
		P95         nativePeeringRate  `json:"known_eligible_p95"`
	}
	out := struct {
		flow.PeeringEstimateResponse
		Target  target                              `json:"target"`
		Bytes   map[string]mcp.NativePeeringCounter `json:"bytes"`
		P95     *nativePeeringRate                  `json:"known_eligible_p95,omitempty"`
		Transit []transit                           `json:"transit"`
	}{PeeringEstimateResponse: value, Target: target{value.Target, mcp.NativeRoleUUID(value.Target.ContextID), mcp.NativeRoleUUID(value.Target.InterfaceID), mcp.NativeRoleUUID(value.Target.RouterID), value.Target.IXID, value.Target.LANID}, Bytes: map[string]mcp.NativePeeringCounter{}, Transit: make([]transit, 0, len(value.Transit))}
	// Unavailable targets still contain caller selections. Preserve numeric
	// identities through text redaction only after current public evidence
	// proved the complete target; syntactic validity alone is not provenance.
	if value.Target.Eligible {
		out.Target.IXID = mcp.NativeRoleRevision(value.Target.IXID)
		out.Target.LANID = mcp.NativeRoleRevision(value.Target.LANID)
	}
	for name, count := range value.Bytes {
		out.Bytes[name] = mcp.NativePeeringCounter(count)
	}
	if value.P95 != nil {
		p95 := nativePeeringRateValue(*value.P95)
		out.P95 = &p95
	}
	for _, link := range value.Transit {
		out.Transit = append(out.Transit, transit{mcp.NativeRoleUUID(link.InterfaceID), nativePeeringRateValue(link.P95)})
	}
	return json.Marshal(out)
}

func peeringToolOption(server *Server) (mcp.Option, error) {
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &document); err != nil {
		return nil, err
	}
	schemas, err := nativeMCPInputSchemas(document.Components.Schemas, map[string]any{"flow_peering_estimate": map[string]any{"$ref": "#/components/schemas/PeeringEstimateInput"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithPeeringEstimateBackend(mcpPeeringBackend{server}, schemas, server.beginPeeringQuery), nil
}
