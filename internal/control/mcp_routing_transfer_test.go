// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/flow"
)

func TestRoutingTransferNativeKeepsOwnedReferencesUnderFinancialRedaction(t *testing.T) {
	const contextID = "10000000-0000-4000-8000-000000000001"
	const agreementID = "10000000-0000-4000-8000-000000000002"
	const syntheticPAN = "4111111111111111"
	value := routingTransferResponse{ContextID: contextID, Estimate: flow.RoutingTransferEstimate{
		Source: &flow.RoutingTransferBill{AgreementID: agreementID, Version: "1", After: flow.CapacityBillResult{ChargeNumerator: syntheticPAN}},
	}}
	raw, err := marshalNativeRoutingTransfer(value)
	if err != nil {
		t.Fatal(err)
	}
	redactor := ai.NewEgressGate(nil, nil, ai.RedactionPolicy{})
	var got routingTransferResponse
	if err := json.Unmarshal([]byte(redactor.RedactForTenant(string(raw), contextID)), &got); err != nil {
		t.Fatal(err)
	}
	if got.ContextID != contextID || got.Estimate.Source == nil || got.Estimate.Source.AgreementID != agreementID ||
		got.Estimate.Source.Version != "1" || got.Estimate.Source.After.ChargeNumerator == syntheticPAN {
		t.Fatal("native output lost a canonical reference or bypassed mandatory financial text redaction")
	}
	if option, err := routingTransferToolOption(&Server{}); err != nil || option == nil {
		t.Fatal("native routing transfer inputs diverged from OpenAPI", err)
	}
}
