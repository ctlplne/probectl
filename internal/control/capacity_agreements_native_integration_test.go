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

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapacityAgreementNativeTLSAndStdioKeepCurrentFinancialTenantAuthority(t *testing.T) {
	for _, transport := range []string{"https", "stdio"} {
		for _, wire := range []string{"2026-07-28", "2025-11-25"} {
			t.Run(transport+"/"+wire, func(t *testing.T) {
				f := newRoleExplanationAPIFixture(t)
				f.server.cfg.FlowQueryLibraryBytes = 256 << 20
				f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
				for _, tenant := range f.tenants {
					f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
						for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite} {
							if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
								return err
							}
						}
						return nil
					})
				}
				seedInterfaceRoleMCPConsent(f)
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
				runCapacityAgreementNativeScenario(t, f, call)
			})
		}
	}
}

func runCapacityAgreementNativeScenario(t *testing.T, f *roleExplanationAPIFixture, call func(string, string, any, any, bool)) {
	t.Helper()
	a, b := f.tenants[0], f.tenants[1]
	definition := flow.CapacityAgreementDefinition{Name: "WAN financial terms", Reference: "recorded agreement", ValidFrom: "2026-11-01T00:00:00.123456789Z", Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 31, Timezone: "Asia/Kathmandu", Direction: "interval_sum", Currency: "USD", CommitBPS: "100000000000", UnitBPS: "1000000", UnitPrice: "1.25"}
	items := map[string]flow.CapacityAgreement{}
	for _, tenant := range f.tenants {
		var item flow.CapacityAgreement
		call(tenant, "capacity_agreement_create", map[string]any{"definition": definition}, &item, true)
		if item.ID == "" || item.Version != "1" || !item.TargetPresent || item.Definition.UnitPrice != definition.UnitPrice || item.Definition.ValidFrom != definition.ValidFrom || item.Definition.Target.InterfaceID != f.interfaceID {
			t.Fatal("actual native financial create lost complete exact/current-owned terms", item)
		}
		items[tenant] = item
		var page flow.CapacityAgreementPage
		call(tenant, "capacity_agreements_list", map[string]any{"limit": 1001}, &page, true)
		if len(page.Items) != 1 || page.Items[0].ID != item.ID || page.HasMore {
			t.Fatal("actual native financial catalog crossed tenants or a fixed row ceiling", page)
		}
	}
	var item flow.CapacityAgreement
	call(a, "capacity_agreement_get", map[string]any{"id": items[b].ID}, nil, false)
	revised := definition
	revised.ValidFrom, revised.UnitPrice = "2026-12-01T00:00:00.123456789Z", "-0.125"
	call(a, "capacity_agreement_update", map[string]any{"id": items[a].ID, "version": "1", "definition": revised}, &item, true)
	if item.Version != "2" || item.Definition.UnitPrice != revised.UnitPrice {
		t.Fatal("actual native revision rounded signed financial terms", item)
	}
	call(a, "capacity_agreement_update", map[string]any{"id": items[a].ID, "version": "1", "definition": definition}, nil, false)
	call(a, "capacity_agreement_get", map[string]any{"id": items[a].ID, "at": "2026-11-30T23:59:59.999999999Z"}, &item, true)
	if item.Version != "1" || item.CurrentVersion != "2" || item.Definition.UnitPrice != definition.UnitPrice {
		t.Fatal("actual native effective terms lost original revision", item)
	}
	call(a, "capacity_agreement_get", map[string]any{"id": items[a].ID, "at": "0001-01-01T00:00:00Z"}, nil, false)
	var history flow.CapacityAgreementPage
	call(a, "capacity_agreement_revisions", map[string]any{"id": items[a].ID, "limit": 1}, &history, true)
	if len(history.Items) != 1 || history.Items[0].Version != "2" || !history.HasMore || history.Next != "2" {
		t.Fatal("actual native recording-order page lost complete continuation", history)
	}
	call(a, "capacity_agreement_revisions", map[string]any{"id": items[a].ID, "after": history.Next, "limit": 1}, &history, true)
	if len(history.Items) != 1 || history.Items[0].Version != "1" || history.HasMore {
		t.Fatal("actual native history omitted oldest financial terms", history)
	}
	for _, permission := range []string{permFlowAgreementsWrite, permFlowAgreementsRead} {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
			return err
		})
		if permission == permFlowAgreementsWrite {
			call(a, "capacity_agreement_delete", map[string]any{"id": items[a].ID, "version": "2"}, nil, false)
			call(a, "capacity_agreement_get", map[string]any{"id": items[a].ID}, &item, true)
		} else {
			call(a, "capacity_agreement_get", map[string]any{"id": items[a].ID}, nil, false)
		}
		call(b, "capacity_agreement_get", map[string]any{"id": items[b].ID}, &item, true)
		if item.ID != items[b].ID || item.Definition.UnitPrice != definition.UnitPrice {
			t.Fatal("financial refusal changed sibling original terms", item)
		}
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
	call(a, "capacity_agreement_delete", map[string]any{"id": items[a].ID, "version": "2"}, nil, true)
	call(a, "capacity_agreement_get", map[string]any{"id": items[a].ID}, nil, false)
	if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
		t.Fatal(err)
	}
	call(a, "capacity_agreements_list", map[string]any{}, nil, false)
	call(b, "capacity_agreement_get", map[string]any{"id": items[b].ID}, &item, true)
}
