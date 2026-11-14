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

func (b mcpCapacityAgreementBackend) carrierSLA(ctx context.Context, input mcp.CapacityAgreementCommand) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/flows/capacity/agreements/"+input.ID+"/sla", nil)
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
	result, publication, err := b.server.calculateCarrierSLA(op, input.ID, flow.CarrierSLARequest{Version: input.Version, At: input.At})
	if err != nil {
		return nil, carrierSLAAPIError(err)
	}
	// Financial text and computed amounts keep the standing full PII floor.
	body, err := marshalNativeCarrierSLA(result, op.budget.MemoryBytes, op.budget.ResponseBytes)
	if err != nil {
		return nil, err
	}
	final := func(_ context.Context) error {
		bound := op.request.Context()
		if err := mcp.CheckOriginatingCredential(bound); err != nil {
			return err
		}
		if !result.SourceValidUntil.After(time.Now().UTC()) {
			return apierror.Unavailable("SLA source validity elapsed; run a fresh calculation")
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

func marshalNativeCarrierSLA(result flow.CarrierSLAStatement, memory, response int64) (json.RawMessage, error) {
	type source struct {
		flow.CarrierSLAPopulation
		Context mcp.NativeRoleUUID `json:"context_id"`
		Device  mcp.NativeRoleUUID `json:"device_id"`
		Test    mcp.NativeRoleUUID `json:"test_id"`
		Agent   any                `json:"agent_id"`
	}
	native := struct {
		flow.CarrierSLAStatement
		Agreement nativeCapacityAgreementValue `json:"agreement"`
		Sources   []source                     `json:"sources"`
	}{CarrierSLAStatement: result, Agreement: nativeCapacityAgreement(result.Agreement), Sources: make([]source, 0, len(result.Sources))}
	for _, item := range result.Sources {
		var agent any = item.AgentID
		canonical := mcp.NativeRoleUUID(item.AgentID)
		if _, err := json.Marshal(canonical); err == nil {
			agent = canonical
		}
		native.Sources = append(native.Sources, source{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.DeviceID), mcp.NativeRoleUUID(item.TestID), agent})
	}
	body, err := json.Marshal(native)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= response || int64(len(body)) >= memory/16 {
		return nil, apierror.TooLarge("complete native SLA output exceeds resource admission")
	}
	return body, nil
}
