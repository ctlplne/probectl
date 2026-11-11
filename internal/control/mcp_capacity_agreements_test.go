// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

func TestCapacityAgreementNativeMetadataKeepsServerIdentityAndFullPriceTextRedaction(t *testing.T) {
	const id = "41111111-1111-4111-8111-111111111111"
	const card = "4111111111111111"
	item := flow.CapacityAgreement{ID: id, Version: card, CurrentVersion: card,
		Definition: flow.CapacityAgreementDefinition{Name: "reader@example.test", Reference: card, UnitPrice: card, Currency: "USD"}}
	raw, err := json.Marshal(nativeCapacityAgreement(item))
	if err != nil {
		t.Fatal(err)
	}
	gate := ai.NewEgressGate(nil, nil, ai.RedactionPolicy{})
	redacted := gate.RedactForTenant(string(raw), "red")
	var decoded flow.CapacityAgreement
	if err := json.Unmarshal([]byte(redacted), &decoded); err != nil || decoded.ID != id || decoded.Version != card || decoded.CurrentVersion != card {
		t.Fatal("server financial metadata was narrowed by text redaction", err)
	}
	if decoded.Definition.Name == item.Definition.Name || decoded.Definition.Reference == card || decoded.Definition.UnitPrice == card {
		t.Fatal("operator financial text or prices bypassed standing PII redaction")
	}
	page, err := marshalCapacityAgreementPage(flow.CapacityAgreementPage{Items: []flow.CapacityAgreement{item}, Next: card, HasMore: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	var result flow.CapacityAgreementPage
	if err := json.Unmarshal([]byte(gate.RedactForTenant(string(page), "red")), &result); err != nil || result.Next != card || len(result.Items) != 1 {
		t.Fatal("native recording-order continuation lost exact metadata", err)
	}
	if option, err := capacityAgreementToolOption(testServer(nil)); err != nil || option == nil {
		t.Fatal("financial tool schema diverged from the declared API", err)
	}
}

func TestCapacityAgreementNativeServiceRejectsContradictoryCredentialBeforeStorage(t *testing.T) {
	foreign := &auth.Principal{TenantID: "red", UserID: "red-user"}
	actor := &auth.Principal{TenantID: "blue", UserID: "blue-user"}
	ctx := auth.WithPrincipal(t.Context(), foreign)
	_, err := (mcpCapacityAgreementBackend{&Server{}}).CapacityAgreements(ctx, actor, "capacity_agreements_list", mcp.CapacityAgreementCommand{})
	domain, ok := apierror.As(err)
	if !ok || !strings.Contains(domain.Error(), "scope does not match") {
		t.Fatal("native financial service replaced a contradictory credential before storage", err)
	}
}
