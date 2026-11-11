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

func (b mcpCapacityAgreementBackend) capacityAgreementBill(ctx context.Context, input mcp.CapacityAgreementCommand) (json.RawMessage, error) {
	if input.Check == nil {
		return nil, apierror.Validation("complete bill check input is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/flows/capacity/agreements/"+input.ID+"/check", nil)
	if err != nil {
		return nil, err
	}
	op, err := b.server.beginCapacityAgreementMode(request, false)
	if err != nil {
		return nil, capacityAgreementAPIError(err)
	}
	defer op.done()
	result, err := b.server.checkCapacityAgreementBill(op, input.ID, *input.Check)
	if err != nil {
		return nil, capacityBillAPIError(err)
	}
	body, err := marshalNativeCapacityBill(result)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return nil, apierror.TooLarge("complete measured billing output exceeds resource admission")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return nil, apierror.Unavailable("counter source authority expired; run a fresh bill check")
	}
	// The MCP publication boundary refreshes the exact originating HTTPS or
	// persistent stdio credential after invocation and mandatory full redaction.
	return body, op.request.Context().Err()
}

type nativeCapacityBillMember struct {
	flow.CapacityBillMember
	ContextID   mcp.NativeRoleUUID `json:"context_id"`
	DeviceID    mcp.NativeRoleUUID `json:"device_id"`
	InterfaceID mcp.NativeRoleUUID `json:"interface_id"`
}

func marshalNativeCapacityBill(result flow.CapacityAgreementBill) (json.RawMessage, error) {
	native := struct {
		flow.CapacityAgreementBill
		Agreement nativeCapacityAgreementValue `json:"agreement"`
		Members   []nativeCapacityBillMember   `json:"members"`
	}{CapacityAgreementBill: result, Agreement: nativeCapacityAgreement(result.Agreement), Members: make([]nativeCapacityBillMember, 0, len(result.Members))}
	for _, member := range result.Members {
		native.Members = append(native.Members, nativeCapacityBillMember{member, mcp.NativeRoleUUID(member.ContextID), mcp.NativeRoleUUID(member.DeviceID), mcp.NativeRoleUUID(member.InterfaceID)})
	}
	// Operator assumptions, invoice text, prices and computed amounts keep
	// ordinary PII/PAN redaction. Only authorized canonical IDs are encoded.
	return json.Marshal(native)
}
