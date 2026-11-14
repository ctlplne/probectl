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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real TLS/native HTTP, authenticated persistent stdio and application-role
// Postgres/RLS. Poll rows and issued sender identities are modeled.
func TestPathHealthAlertNativeTLSAndStdioKeepCurrentTenantSourceAuthority(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { provePathHealthAlertNative(t, wire) })
	}
}

func provePathHealthAlertNative(t *testing.T, wire string) {
	t.Helper()
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAIQuery, permAlertRead, permAlertWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
	}
	seedInterfaceRoleMCPConsent(f)
	call := interfaceRoleNativeTLSCaller(t, f, wire)
	rules := map[string]alert.Rule{}
	for _, tenant := range f.tenants {
		input := alert.PathHealthSourceInput{TestID: proof.tests[tenant], InterfaceID: f.interfaceID, Metric: "probectl.device.if.in.fcs.errors"}
		var rule alert.Rule
		call(tenant, "alert_path_health_create", map[string]any{"name": "Owned source 192.0.2.1", "path_health_source": input}, &rule, true)
		if rule.ID == "" || rule.TenantID != tenant || rule.Name == "Owned source 192.0.2.1" {
			t.Fatal("native creation changed canonical IDs or bypassed full free-text redaction")
		}
		rules[tenant] = rule
		var state alert.PathHealthSourceState
		call(tenant, "alert_path_health_get", map[string]any{"rule_id": rule.ID}, &state, true)
		if state.RuleID != rule.ID || !state.Configured || state.Source == nil || state.Source.TestID != proof.tests[tenant] || state.Source.InterfaceID != f.interfaceID || state.Source.Metric != input.Metric {
			t.Fatal("native source lost current canonical parents or original error category")
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	call(a, "alert_path_health_get", map[string]any{"rule_id": rules[b].ID}, nil, false)
	call(a, "alert_path_health_get", map[string]any{"rule_id": rules[a].ID, "tenant_id": b}, nil, false)
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	for _, tenant := range f.tenants {
		streams[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		var state alert.PathHealthSourceState
		streams[tenant].call(t, wire, "alert_path_health_get", map[string]any{"rule_id": rules[tenant].ID}, &state, true)
		if state.Source == nil || state.Source.TestID != proof.tests[tenant] {
			t.Fatal("persistent source inspection lost tenant identity")
		}
	}
	proof.history.after = func() {
		proof.history.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, "DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'", a, f.roles[a])
			return err
		})
	}
	streams[a].call(t, wire, "alert_path_health_get", map[string]any{"rule_id": rules[a].ID}, nil, false)
	var sibling alert.PathHealthSourceState
	streams[b].call(t, wire, "alert_path_health_get", map[string]any{"rule_id": rules[b].ID}, &sibling, true)
	if sibling.Source == nil || sibling.Source.TestID != proof.tests[b] {
		t.Fatal("one tenant's late grant withdrawal changed its sibling")
	}
	var cleared alert.PathHealthSourceState
	streams[a].call(t, wire, "alert_path_health_clear", map[string]any{"rule_id": rules[a].ID, "confirmed": true}, &cleared, true)
	if cleared.Configured || cleared.Source != nil {
		t.Fatal("write-only clear retained an active source")
	}
}
