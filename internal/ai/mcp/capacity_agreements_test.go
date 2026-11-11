// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

type capacityAgreementProbe struct {
	tenants []string
	command CapacityAgreementCommand
}

func (b *capacityAgreementProbe) CapacityAgreements(_ context.Context, p *auth.Principal, _ string, input CapacityAgreementCommand) (json.RawMessage, error) {
	b.tenants = append(b.tenants, p.TenantID)
	b.command = input
	return json.RawMessage("{}"), nil
}

func TestCapacityAgreementNativeToolsKeepExactTermsAndSeparateTenantFinancialGrants(t *testing.T) {
	b := &capacityAgreementProbe{}
	schemas := NativeFlowSchemas{}
	for _, item := range capacityAgreementTools {
		raw, _ := json.Marshal(map[string]string{"type": "object"})
		schemas[item.name] = raw
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithCapacityAgreementBackend(b, schemas, 8<<20))
	definition := flow.CapacityAgreementDefinition{Name: "WAN", ValidFrom: "9999-12-31T23:59:59.999999999Z", Target: flow.CapacityTarget{Kind: "interface", ContextID: tagWriteTestID, InterfaceID: tagWriteTestID}, BillingDay: 31, Timezone: "UTC", Direction: "interval_sum", Currency: "USD", CommitBPS: "100000000000.000000000000000001", UnitBPS: "1000000", UnitPrice: "-0.000000000000000000000000000001"}
	for _, tenant := range []string{"red", "blue"} {
		p := principal(tenant, "flow.agreements.read", "flow.agreements.write")
		p.UserID = "financial-reader"
		for _, tool := range capacityAgreementTools {
			args := map[string]any{}
			if tool.name != "capacity_agreements_list" && tool.name != "capacity_agreement_create" {
				args["id"] = tagWriteTestID
			}
			if tool.name == "capacity_agreement_create" || tool.name == "capacity_agreement_update" {
				args["definition"] = definition
			}
			if tool.name == "capacity_agreement_update" || tool.name == "capacity_agreement_delete" {
				args["version"] = "9007199254740993"
			}
			if tool.name == "capacity_agreement_bill_check" {
				args["check"] = flow.CapacityBillRequest{Version: "9007199254740993", At: "2026-10-15T00:00:00Z", MaximumPollGap: "5m", PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: tagWriteTestID, InterfaceID: tagWriteTestID, MaxBPS: "18446744073709551615"}}}
			}
			before := len(b.tenants)
			response := handle(t, server, p, 1, "tools/call", map[string]any{"name": tool.name, "arguments": args})
			if len(b.tenants) != before+1 || b.tenants[before] != tenant || resultOf(t, response)["isError"] == true {
				t.Fatal("financial native operation lost user/tenant or required an unrelated telemetry grant", tool.name, response)
			}
			if tool.name == "capacity_agreement_update" && (b.command.Version != "9007199254740993" || b.command.Definition == nil || !reflect.DeepEqual(*b.command.Definition, definition)) {
				t.Fatal("native terms rounded the revision, clock or financial decimals")
			}
			for _, denied := range []*auth.Principal{principal(tenant, "flow.read"), principal(tenant, "flow.agreements.write")} {
				denied.UserID = "financial-reader"
				before := len(b.tenants)
				handle(t, server, denied, 2, "tools/call", map[string]any{"name": tool.name, "arguments": args})
				if len(b.tenants) != before {
					t.Fatal("financial command reached storage without its independent read grant", tool.name)
				}
			}
			noUser := principal(tenant, "flow.agreements.read", "flow.agreements.write")
			before = len(b.tenants)
			handle(t, server, noUser, 3, "tools/call", map[string]any{"name": tool.name, "arguments": args})
			if len(b.tenants) != before {
				t.Fatal("service-only identity reached current-user financial terms")
			}
		}
	}
}

func TestCapacityAgreementNativeArgumentsRefuseAuthorityHintsAndAmbiguousOperations(t *testing.T) {
	for _, input := range []struct{ name, raw string }{
		{"capacity_agreements_list", `{"tenant_id":"foreign"}`},
		{"capacity_agreement_bill_check", `{"id":"` + tagWriteTestID + `"}`},
		{"capacity_agreement_get", `{"id":"` + tagWriteTestID + `","check":{}}`},
		{"capacity_agreement_bill_check", `{"id":"` + tagWriteTestID + `","check":{},"version":"1"}`},
		{"capacity_agreements_list", `{"limit":0}`},
		{"capacity_agreements_list", `{"limit":-1}`},
		{"capacity_agreements_list", `{"limit":1,"limit":2}`},
		{"capacity_agreement_get", `{"id":"` + tagWriteTestID + `","version":"01"}`},
		{"capacity_agreement_get", `{"id":"` + tagWriteTestID + `","version":"1","at":"2026-11-01T00:00:00Z"}`},
		{"capacity_agreement_get", `{"id":"` + tagWriteTestID + `","at":"missing-zone"}`},
		{"capacity_agreement_create", `{}`},
		{"capacity_agreement_delete", `{"id":"` + tagWriteTestID + `","version":9007199254740993}`},
		{"capacity_agreement_revisions", `{"id":"` + tagWriteTestID + `","after":"foreign"}`},
	} {
		if _, err := decodeCapacityAgreementCommand(json.RawMessage(input.raw), input.name, 8<<20); err == nil {
			t.Fatal("native financial input accepted authority or a different operation shape", input)
		}
	}
}
