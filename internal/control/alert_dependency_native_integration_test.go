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
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestTopologyDependencyNativeConfigurationKeepsCurrentTenantsAndReadCeilings(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f, rules := newDependencyAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			call := interfaceRoleNativeTLSCaller(t, f, wire)
			input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300}
			for i, tenant := range f.tenants {
				id, foreign := rules[tenant].ID, rules[f.tenants[1-i]].ID
				var state alert.DependencyPolicyState
				call(tenant, "alert_dependency_set", map[string]any{"rule_id": id, "input": input}, &state, true)
				if state.RuleID != id || !state.Configured || state.Policy == nil || *state.Policy != input {
					t.Fatal("native configuration lost its current tenant/context", state)
				}
				call(tenant, "alert_dependency_get", map[string]any{"rule_id": id}, &state, true)
				if state.RuleID != id || !state.Configured || state.Policy == nil || *state.Policy != input {
					t.Fatal("native inspection lost complete current configuration", state)
				}
				call(tenant, "alert_dependency_get", map[string]any{"rule_id": foreign}, nil, false)
				call(tenant, "alert_dependency_set", map[string]any{"rule_id": foreign, "input": input}, nil, false)
				call(tenant, "alert_dependency_clear", map[string]any{"rule_id": foreign, "confirmed": true}, nil, false)
				call(tenant, "alert_dependency_set", map[string]any{"rule_id": id, "input": map[string]any{"context_id": f.contextID, "owner_user_id": f.users[f.tenants[1-i]]}}, nil, false)
				call(tenant, "alert_dependency_clear", map[string]any{"rule_id": id, "confirmed": false}, nil, false)
				f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='topology.read'`, tenant, f.roles[tenant])
					return err
				})
				call(tenant, "alert_dependency_get", map[string]any{"rule_id": id}, nil, false)
				call(tenant, "alert_dependency_set", map[string]any{"rule_id": id, "input": input}, nil, false)
				state = alert.DependencyPolicyState{}
				call(tenant, "alert_dependency_clear", map[string]any{"rule_id": id, "confirmed": true}, &state, true)
				if state.RuleID != id || state.Configured || state.Policy != nil {
					t.Fatal("write-only native clear retained source configuration", state)
				}
				f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					current, err := (store.AlertRules{}).Get(ctx, sc, id)
					if err != nil {
						return err
					}
					if !current.Enabled || current.HasDependencyPolicy || current.Metric != rules[tenant].Metric {
						t.Fatal("native dependency clear changed detection", current)
					}
					return nil
				})
			}
		})
	}
	t.Log("real-integration: paired app-role PG and authenticated verified HTTPS MCP on both wire versions; configured read ceiling/current grants, source-authority injection refusal and write-only clear; no routing or physical-source claim")
}
