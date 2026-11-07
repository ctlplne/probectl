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
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual persistent shipped stdio transports, token refresh, current grants,
// application-role Postgres/RLS and configuration audit. Router/source registry
// identities are modeled; there is no physical BMP or route/flow claim.
func TestBGPRoutingBindingsStdioKeepsTenantEpochAndCurrentCredentials(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f := newRoleExplanationAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			cfg := &config.Config{}
			server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
			authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
			clients := []*interfaceRoleStdioClient{
				openInterfaceRoleStdio(t, server, authenticator, f.tokens[f.tenants[0]], wire),
				openInterfaceRoleStdio(t, server, authenticator, f.tokens[f.tenants[1]], wire),
			}
			read := map[string]any{"context_id": f.contextID, "collector_agent_id": "role-listener", "source_ref": "role-router"}
			bindings := []store.BGPRoutingBinding{{ContextID: f.contextID, RouterID: f.routerID, Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{1, 2}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1}}
			write := map[string]any{"context_id": f.contextID, "collector_agent_id": "role-listener", "source_ref": "role-router", "expected_epoch": "", "bindings": bindings}
			current := make([]store.BGPRoutingBindingConfiguration, 2)
			for lane, client := range clients {
				client.call(t, wire, "bgp_routing_bindings", read, &current[lane], true)
				if current[lane].Manifest != nil || current[lane].ContextID != f.contextID {
					t.Fatal("native routing read lost the owned strict default")
				}
				client.call(t, wire, "bgp_routing_bindings_replace", write, &current[lane], true)
				if current[lane].Manifest == nil || len(current[lane].Manifest.Bindings) != 1 || current[lane].Manifest.Bindings[0].SourceFormat != store.BGPRoutingSourceFRRLocRIBV1 || len(current[lane].Manifest.Bindings[0].Families) != 2 {
					t.Fatal("native routing replacement lost complete owned configuration")
				}
				client.call(t, wire, "bgp_routing_bindings_replace", write, nil, false)
			}
			const canonical = "40000000-0000-4004-8000-abcdefabcdef"
			f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				// Model a possible server-generated UUID with a PAN-shaped
				// prefix; no source/operator text receives this exemption.
				_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET routing_bindings=jsonb_set(routing_bindings,'{0,id}',to_jsonb($2::text)) WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, f.tenants[0], canonical)
				return err
			})
			for lane, client := range clients {
				var got store.BGPRoutingBindingConfiguration
				client.call(t, wire, "bgp_routing_bindings", read, &got, true)
				if got.Manifest == nil || got.Manifest.Epoch != current[lane].Manifest.Epoch || got.Manifest.Epoch == current[1-lane].Manifest.Epoch {
					t.Fatal("native routing configuration crossed a tenant epoch")
				}
				if lane == 0 && got.Manifest.Bindings[0].ID != canonical {
					t.Fatal("native routing metadata changed canonical binding identity")
				}
			}
			f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='agent.write'`, f.tenants[0], f.roles[f.tenants[0]])
				return err
			})
			write["expected_epoch"] = current[0].Manifest.Epoch
			write["bindings"] = []store.BGPRoutingBinding{}
			clients[0].call(t, wire, "bgp_routing_bindings_replace", write, nil, false)
			f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[f.tenants[0]], "agent.write")
			})
			var withdrawn store.BGPRoutingBindingConfiguration
			clients[0].call(t, wire, "bgp_routing_bindings_replace", write, &withdrawn, true)
			if withdrawn.Manifest == nil || len(withdrawn.Manifest.Bindings) != 0 || withdrawn.Manifest.Epoch == current[0].Manifest.Epoch {
				t.Fatal("native routing withdrawal restored a fallback or retained its epoch")
			}
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), f.tenants[0], f.users[f.tenants[0]]); err != nil {
				t.Fatal(err)
			}
			clients[0].call(t, wire, "bgp_routing_bindings", read, nil, false)
			var sibling store.BGPRoutingBindingConfiguration
			clients[1].call(t, wire, "bgp_routing_bindings", read, &sibling, true)
			if sibling.Manifest == nil || sibling.Manifest.Epoch != current[1].Manifest.Epoch || len(sibling.Manifest.Bindings) != 1 {
				t.Fatal("native credential revocation changed the paired routing tenant")
			}
		})
	}
}
