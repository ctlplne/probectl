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

func (b mcpCapacityAgreementBackend) capacityForecast(ctx context.Context, input mcp.CapacityAgreementCommand) (json.RawMessage, error) {
	if input.Forecast == nil {
		return nil, apierror.Validation("complete forecast input is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/flows/capacity/forecast", nil)
	if err != nil {
		return nil, err
	}
	op, err := b.server.beginCapacityForecast(request)
	if err != nil {
		return nil, capacityBillAPIError(err)
	}
	defer op.done()
	result, err := b.server.measureCapacityForecast(op, *input.Forecast)
	if err != nil {
		return nil, capacityBillAPIError(err)
	}
	native := struct {
		flow.CapacityForecastMeasurement
		Target  nativeCapacityTarget       `json:"target"`
		Members []nativeCapacityBillMember `json:"members"`
	}{CapacityForecastMeasurement: result, Target: nativeCapacityTarget{result.Target, mcp.NativeRoleUUID(result.Target.ContextID), mcp.NativeRoleUUID(result.Target.InterfaceID), mcp.NativeRoleUUID(result.Target.TagID)}, Members: make([]nativeCapacityBillMember, 0, len(result.Members))}
	for _, member := range result.Members {
		native.Members = append(native.Members, nativeCapacityBillMember{member, mcp.NativeRoleUUID(member.ContextID), mcp.NativeRoleUUID(member.DeviceID), mcp.NativeRoleUUID(member.InterfaceID)})
	}
	body, err := json.Marshal(native)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= op.budget.ResponseBytes || int64(len(body)) >= op.budget.MemoryBytes/16 {
		return nil, apierror.TooLarge("complete forecast output exceeds resource admission")
	}
	if !result.SourceValidUntil.After(time.Now().UTC()) {
		return nil, apierror.Unavailable("forecast source authority expired; retry")
	}
	return body, op.request.Context().Err()
}
