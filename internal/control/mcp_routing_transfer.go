// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

func (s *Server) readNativeRoutingTransfer(ctx context.Context, actor *auth.Principal, raw json.RawMessage) (json.RawMessage, error) {
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/flows/routing-transfer-estimate", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	op, err := s.beginCapacityAgreementMode(request, false)
	if err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	retained := false
	defer func() {
		if !retained {
			op.done()
		}
	}()
	var input routingTransferRequest
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return nil, err
	}
	result, err := s.runRoutingTransferEstimate(op.request.Context(), op, input)
	if err != nil {
		return nil, routingTransferAPIError(err)
	}
	body, err := marshalNativeRoutingTransfer(result)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return nil, apierror.TooLarge("complete routing transfer output exceeds resource admission")
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		if err := active.Err(); err != nil {
			return err
		}
		bound := op.request.Context()
		if err := mcp.CheckOriginatingCredential(bound); err != nil {
			return err
		}
		if err := result.check(bound); err != nil {
			return routingTransferAPIError(err)
		}
		return nil
	}, op.done); err != nil {
		return nil, err
	}
	retained = true
	return body, nil
}

func marshalNativeRoutingTransfer(value routingTransferResponse) (json.RawMessage, error) {
	type bill struct {
		flow.RoutingTransferBill
		AgreementID mcp.NativeRoleUUID     `json:"agreement_id"`
		Version     mcp.NativeRoleRevision `json:"agreement_version"`
	}
	type estimate struct {
		flow.RoutingTransferEstimate
		Source    *bill `json:"source,omitempty"`
		Candidate *bill `json:"candidate,omitempty"`
	}
	type policy struct {
		routingTransferPolicy
		RouterID mcp.NativeRoleUUID `json:"router_id"`
	}
	out := struct {
		routingTransferResponse
		ContextID mcp.NativeRoleUUID `json:"context_id"`
		Estimate  estimate           `json:"estimate"`
		Policy    *policy            `json:"policy,omitempty"`
	}{routingTransferResponse: value, ContextID: mcp.NativeRoleUUID(value.ContextID), Estimate: estimate{RoutingTransferEstimate: value.Estimate}}
	if value.Policy != nil {
		out.Policy = &policy{*value.Policy, mcp.NativeRoleUUID(value.Policy.RouterID)}
	}
	if source := value.Estimate.Source; source != nil {
		out.Estimate.Source = &bill{*source, mcp.NativeRoleUUID(source.AgreementID), mcp.NativeRoleRevision(source.Version)}
	}
	if candidate := value.Estimate.Candidate; candidate != nil {
		out.Estimate.Candidate = &bill{*candidate, mcp.NativeRoleUUID(candidate.AgreementID), mcp.NativeRoleRevision(candidate.Version)}
	}
	return json.Marshal(out)
}

func routingTransferToolOption(server *Server) (mcp.Option, error) {
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	name := mcp.RoutingTransferToolName
	schemas, err := nativeMCPInputSchemas(doc.Components.Schemas, map[string]any{name: map[string]any{"$ref": "#/components/schemas/RoutingTransferInput"}})
	if err != nil {
		return nil, err
	}
	return mcp.WithRoutingTransferEstimate(schemas[name], server.readNativeRoutingTransfer), nil
}
