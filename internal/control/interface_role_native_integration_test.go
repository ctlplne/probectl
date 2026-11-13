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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual modern/legacy native HTTP, verified TLS, bearer authentication and
// current Postgres permissions/configuration. Sender identities are seeded;
// this root does not claim real SNMP/BMP or stdio process proof.
func TestInterfaceRoleNativeTLSKeepsTenantConfigurationAndCurrentSources(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { proveInterfaceRoleNativeTLS(t, wire) })
	}
}

func proveInterfaceRoleNativeTLS(t *testing.T, wire string) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	seedInterfaceRoleMCPConsent(f)
	call := interfaceRoleNativeTLSCaller(t, f, wire)
	a, b := f.tenants[0], f.tenants[1]
	readArgs := map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID}
	explain := func(tenant string, want entity.InterfaceRole) {
		t.Helper()
		var out interfaceRoleExplanation
		call(tenant, "interface_role_explain", readArgs, &out, true)
		if out.TenantID != tenant || out.ContextID != f.contextID || out.InterfaceID != f.interfaceID || out.Role != want || len(out.Sources) == 0 {
			t.Fatal("native role response lost current tenant/source identity", out)
		}
	}
	explain(a, entity.InterfaceRoleTransit)
	explain(b, entity.InterfaceRoleTransit)
	var policy entity.InterfaceRolePolicyRecord
	call(a, "interface_role_policy", map[string]any{"context_id": f.contextID}, &policy, true)
	if policy.TenantID != a || len(policy.Definition.ProviderASNs) != 1 || policy.Definition.ProviderASNs[0] != 64496 {
		t.Fatal("native policy used the untrusted tenant hint", policy)
	}
	var saved entity.InterfaceRoleOverrideRecord
	call(a, "interface_role_override_set", map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID, "expected_id": "", "expected_revision": "0", "role": "private_peering"}, &saved, true)
	if saved.TenantID != a || saved.ID == "" || saved.Revision != "1" || saved.Role != entity.InterfaceRolePrivate {
		t.Fatal("native override lost tenant incarnation", saved)
	}
	var retained entity.InterfaceRoleOverrideRecord
	call(a, "interface_role_override", readArgs, &retained, true)
	if retained.ID != saved.ID || retained.Revision != saved.Revision {
		t.Fatal("native override read lost exact incarnation", retained)
	}
	explain(a, entity.InterfaceRolePrivate)
	explain(b, entity.InterfaceRoleTransit)
	call(a, "interface_role_override_reset", map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID, "expected_id": saved.ID, "expected_revision": saved.Revision, "confirmed": true}, nil, true)
	explain(a, entity.InterfaceRoleTransit)
	// The complete saved policy remains complete through actual RPC framing and
	// bounded redaction, rather than only a mocked native backend.
	saveCompleteRoleExplanationPolicy(f, a)
	call(a, "interface_role_policy", map[string]any{"context_id": f.contextID}, &policy, true)
	if len(policy.Definition.DescriptionRules) != 4097 {
		t.Fatal("native role policy truncated the complete saved workload", len(policy.Definition.DescriptionRules))
	}
	var same entity.InterfaceRolePolicyRecord
	call(a, "interface_role_policy_set", map[string]any{"context_id": f.contextID, "expected_id": policy.ID, "expected_revision": policy.Revision, "definition": policy.Definition}, &same, true)
	if same.ID != policy.ID || same.Revision != policy.Revision || len(same.Definition.DescriptionRules) != 4097 {
		t.Fatal("native complete policy changed identity or population", same.ID, same.Revision, len(same.Definition.DescriptionRules))
	}
	explain(a, entity.InterfaceRoleBackbone)
	explain(b, entity.InterfaceRoleTransit)
	for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
			return err
		})
		call(a, "interface_role_explain", readArgs, nil, false)
		explain(b, entity.InterfaceRoleTransit)
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
}
