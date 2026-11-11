// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual TLS PG/application RLS, verified HTTPS and persistent in-process stdio.
// The complete-month counters/receipt rows are modeled, not physical SNMP or a
// fresh issued-sender transport proof.
func TestCapacityAgreementBillNativeCompleteMonthAndCurrentPairedAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	probe := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.flowStore = probe
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		seedCapacityBillingMonth(f, probe.Memory, tenant, from, to)
	}
	seedInterfaceRoleMCPConsent(f)
	definition := flow.CapacityAgreementDefinition{Name: "Recorded interface terms", Reference: "operator contract", ValidFrom: from.Format(time.RFC3339Nano), Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "1000", UnitBPS: "1000", UnitPrice: "0.250000000000000001"}
	check := flow.CapacityBillRequest{Version: "1", At: "2026-10-15T12:00:00Z", MaximumPollGap: "5m", Invoiced: "3.8000000000000000152", PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: f.contextID, InterfaceID: f.interfaceID, MaxBPS: "1000000"}}}
	ids := map[string]string{}
	for _, transport := range []string{"https", "stdio"} {
		for _, wire := range []string{"2026-07-28", "2025-11-25"} {
			t.Run(transport+"/"+wire, func(t *testing.T) {
				var call func(string, string, any, any, bool)
				if transport == "https" {
					call = interfaceRoleNativeTLSCaller(t, f, wire)
				} else {
					cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
					server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
					authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
					clients := map[string]*interfaceRoleStdioClient{}
					for _, tenant := range f.tenants {
						clients[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
					}
					call = func(tenant, name string, input, target any, ok bool) {
						clients[tenant].call(t, wire, name, input, target, ok)
					}
				}
				for _, tenant := range f.tenants {
					if ids[tenant] == "" {
						var item flow.CapacityAgreement
						call(tenant, "capacity_agreement_create", map[string]any{"definition": definition}, &item, true)
						ids[tenant] = item.ID
					}
					var got flow.CapacityAgreementBill
					call(tenant, "capacity_agreement_bill_check", map[string]any{"id": ids[tenant], "check": check}, &got, true)
					assertCapacityMonthBill(t, got, from, to)
					if len(got.Members) != 1 || got.Members[0].InterfaceID != f.interfaceID || got.Members[0].ContextID != f.contextID {
						t.Fatal("canonical native member identity was lost", got.Members)
					}
				}
				a, b := f.tenants[0], f.tenants[1]
				call(a, "capacity_agreement_bill_check", map[string]any{"id": ids[b], "check": check}, nil, false)
				probe.after = func() {
					f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
						_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permFlowAgreementsRead)
						return err
					})
				}
				call(a, "capacity_agreement_bill_check", map[string]any{"id": ids[a], "check": check}, nil, false)
				probe.after = nil
				var sibling flow.CapacityAgreementBill
				call(b, "capacity_agreement_bill_check", map[string]any{"id": ids[b], "check": check}, &sibling, true)
				assertCapacityMonthBill(t, sibling, from, to)
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permFlowAgreementsRead)
				})
			})
		}
	}
}
