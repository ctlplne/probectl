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
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual modern/legacy MCP over verified HTTPS and app-role Postgres/RLS.
// Public evidence and issued identities are seeded; empty memory flow input
// proves honest absence and current authority, not traffic or physical senders.
func TestPeeringNativeTLSKeepsWholeTargetCurrentAuthorityAndUnprovenRedaction(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f, _, input := newPeeringEstimateAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			call := interfaceRoleNativeTLSCaller(t, f, wire)
			a, b := f.tenants[0], f.tenants[1]
			assertEmpty := func(tenant string) {
				t.Helper()
				var out flow.PeeringEstimateResponse
				call(tenant, "flow_peering_estimate", input, &out, true)
				if !out.Preview || !out.Target.Eligible || out.Target.ContextID != f.contextID || out.Target.InterfaceID != f.interfaceID || out.Target.IXID != input.IXID || out.Target.LANID != input.LANID || len(out.Target.MemberIDs) != 5001 || out.P95 != nil || out.Coverage.CompleteObservedInputs || out.Coverage.ExpectedIntervals != 12 || out.Reason != "missing_observed_intervals" {
					t.Fatal("actual native peering lost complete proved target or invented empty-input p95", out)
				}
			}
			assertEmpty(a)
			assertEmpty(b)
			unproved := input
			// Standing synthetic PAN, accepted syntactically as a positive int64
			// but absent from the complete current public IX/LAN evidence.
			unproved.IXID, unproved.LANID = "4111111111111111", "4111111111111111"
			var out flow.PeeringEstimateResponse
			call(a, "flow_peering_estimate", unproved, &out, true)
			if out.Target.Eligible || out.Target.IXID == unproved.IXID || out.Target.LANID == unproved.LANID || out.Reason == "" {
				t.Fatal("actual native peering escaped mandatory redaction for unproved selectors")
			}
			for _, permission := range []string{"flow.read", "ai.query", "entities.read", "metrics.read", "events.read"} {
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
					return err
				})
				call(a, "flow_peering_estimate", input, nil, false)
				assertEmpty(b)
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
				})
			}
			assertEmpty(a)
		})
	}
}

// Persistent authenticated stdio streams exercise production framing and
// per-request credential refresh in process; shipped-process proof is separate.
func TestPeeringNativeStdioKeepsWholeTargetPrivacyAndCurrentCredential(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f, _, input := newPeeringEstimateAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
			server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
			authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
			a, b := f.tenants[0], f.tenants[1]
			first := openInterfaceRoleStdio(t, server, authenticator, f.tokens[a], wire)
			second := openInterfaceRoleStdio(t, server, authenticator, f.tokens[b], wire)
			assertEmpty := func(client *interfaceRoleStdioClient) {
				t.Helper()
				var out flow.PeeringEstimateResponse
				client.call(t, wire, "flow_peering_estimate", input, &out, true)
				if !out.Preview || !out.Target.Eligible || out.Target.ContextID != f.contextID || out.Target.InterfaceID != f.interfaceID || len(out.Target.MemberIDs) != 5001 || out.P95 != nil || out.Coverage.CompleteObservedInputs || out.Reason != "missing_observed_intervals" {
					t.Fatal("persistent native peering lost whole current target or invented absent traffic", out)
				}
			}
			assertEmpty(first)
			assertEmpty(second)
			unproved := input
			unproved.IXID, unproved.LANID = "4111111111111111", "4111111111111111"
			var out flow.PeeringEstimateResponse
			first.call(t, wire, "flow_peering_estimate", unproved, &out, true)
			if out.Target.Eligible || out.Target.IXID == unproved.IXID || out.Target.LANID == unproved.LANID {
				t.Fatal("persistent native peering escaped mandatory unproved-selector redaction")
			}
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Fatal(err)
			}
			first.call(t, wire, "flow_peering_estimate", input, nil, false)
			assertEmpty(second)
		})
	}
}
