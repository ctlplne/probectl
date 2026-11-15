// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
)

func (b mcpCapacityAgreementBackend) carrierSLAClaim(ctx context.Context, input mcp.CapacityAgreementCommand) (json.RawMessage, error) {
	if input.Claim == nil {
		return nil, apierror.Validation("complete recorded SLA selections are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/flows/capacity/sla-claims", nil)
	if err != nil {
		return nil, err
	}
	op, err := b.server.beginCapacityAgreementMode(request, false)
	if err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	retained := false
	defer func() {
		if !retained {
			op.done()
		}
	}()
	result, publication, err := b.server.prepareCarrierSLAClaim(op, *input.Claim)
	if err != nil {
		return nil, carrierSLAAPIError(err)
	}
	body, err := marshalNativeCarrierSLAClaim(result, op.budget.MemoryBytes, op.budget.ResponseBytes)
	if err != nil {
		return nil, err
	}
	final := func(_ context.Context) error {
		bound := op.request.Context()
		if err := mcp.CheckOriginatingCredential(bound); err != nil {
			return err
		}
		if !result.SourceValidUntil.After(time.Now().UTC()) {
			return apierror.Unavailable("claim source validity elapsed; run a fresh draft")
		}
		return publication(bound)
	}
	if err := final(ctx); err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(op.request.Context(), final, op.done); err != nil {
		return nil, err
	}
	retained = true
	return body, nil
}

func marshalNativeCarrierSLAClaim(result flow.CarrierSLAClaimDraft, memory, response int64) (json.RawMessage, error) {
	type group struct {
		flow.CarrierSLAClaimGroup
		Circuits []json.RawMessage `json:"circuits"`
	}
	native := struct {
		flow.CarrierSLAClaimDraft
		Groups []group `json:"groups"`
	}{CarrierSLAClaimDraft: result, Groups: make([]group, 0, len(result.Groups))}
	for _, value := range result.Groups {
		item := group{CarrierSLAClaimGroup: value, Circuits: make([]json.RawMessage, 0, len(value.Circuits))}
		for _, statement := range value.Circuits {
			body, err := marshalNativeCarrierSLA(statement, memory, response)
			if err != nil {
				return nil, err
			}
			item.Circuits = append(item.Circuits, body)
		}
		native.Groups = append(native.Groups, item)
	}
	body, err := json.Marshal(native)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= response || int64(len(body)) >= memory/16 {
		return nil, apierror.TooLarge("complete native SLA claim exceeds resource admission")
	}
	return body, nil
}
