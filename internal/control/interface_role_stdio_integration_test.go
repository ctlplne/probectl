// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual persistent stdio streams, token refresh, RLS/configuration and source
// reads. ixpfx/SNMP/BMP facts are modeled; shipped-process/router proof is owed.
func TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) {
			f := newRoleExplanationAPIFixture(t)
			seedInterfaceRoleMCPConsent(f)
			a, b := f.tenants[0], f.tenants[1]
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				configuration := store.InterfaceRoleConfiguration{}
				old, err := configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
				if err != nil {
					return err
				}
				_, err = configuration.PutPolicy(ctx, sc, f.contextID, old.ID, old.Revision, entity.InterfaceRolePolicyDefinition{}, roleExplanationStoreBudget())
				return err
			})
			f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRolePrivate)
				return err
			})
			ix := roleIXEnricher(t, time.Now().UTC().Add(-time.Minute), "10.42.0.0/24")
			f.server.WithOpenDataStatus(ix, nil, nil)
			cfg := &config.Config{}
			server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
			authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
			first, second := openInterfaceRoleStdio(t, server, authenticator, f.tokens[a], wire), openInterfaceRoleStdio(t, server, authenticator, f.tokens[b], wire)
			args := map[string]any{"context_id": f.contextID, "interface_id": f.interfaceID}
			var explanation interfaceRoleExplanation
			first.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != a || explanation.Role != entity.InterfaceRoleIX || !strings.Contains(strings.Join(explanation.Sources, ","), "/snapshot/"+ix.IXPrefixes(time.Now()).Version) {
				t.Fatal("stdio role lost the owned IX generation", explanation)
			}
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio role crossed tenant source or override authority", explanation)
			}
			saveCompleteRoleExplanationPolicy(f, a)
			var expected, got entity.InterfaceRolePolicyRecord
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				// Model a valid possible generator output whose numeric prefix
				// also passes a PAN checksum. It remains an opaque UUID,
				// without changing any rule/pattern, order or population.
				if _, err := sc.Q.Exec(ctx, `UPDATE interface_role_policies SET definition=jsonb_set(definition,'{description_rules,0,id}',to_jsonb($3::text)) WHERE tenant_id=$1 AND context_id=$2`, a, f.contextID, "40000000-0000-4004-8000-abcdefabcdef"); err != nil {
					return err
				}
				var err error
				expected, err = (store.InterfaceRoleConfiguration{}).Policy(ctx, sc, f.contextID, interfaceRoleStoreBudget(flowstore.DefaultExplorerBudget()))
				return err
			})
			first.call(t, wire, "interface_role_policy", map[string]any{"context_id": f.contextID}, &got, true)
			if got.TenantID != a || len(got.Definition.DescriptionRules) != 4097 || !reflect.DeepEqual(got.Definition, expected.Definition) || got.ID != expected.ID || got.Revision != expected.Revision {
				t.Log("role policy identity/count diagnostics", got.TenantID == a, got.ID == expected.ID, got.Revision == expected.Revision, len(got.Definition.DescriptionRules), len(expected.Definition.DescriptionRules), got.Definition.ProviderASNs, expected.Definition.ProviderASNs, got.Definition.CustomerASNs, expected.Definition.CustomerASNs)
				for i, rule := range got.Definition.DescriptionRules {
					if i < len(expected.Definition.DescriptionRules) && rule != expected.Definition.DescriptionRules[i] {
						original := expected.Definition.DescriptionRules[i]
						t.Log("synthetic rule difference", i, "same_id", rule.ID == original.ID, "same_role", rule.Role == original.Role, "pattern_bytes", len(rule.Pattern), len(original.Pattern), "rendered_synthetic_pattern", rule.Pattern)
						break
					}
				}
				t.Fatal("stdio role changed complete policy values or exact identity")
			}
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
				return err
			})
			first.call(t, wire, "interface_role_explain", args, nil, false)
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio role refusal changed the paired tenant")
			}
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "events.read")
			})
			first.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != a || explanation.Role != entity.InterfaceRoleBackbone {
				t.Fatal("stdio role failed a fresh current authority recovery")
			}
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Fatal(err)
			}
			first.call(t, wire, "interface_role_explain", args, nil, false)
			second.call(t, wire, "interface_role_explain", args, &explanation, true)
			if explanation.TenantID != b || explanation.Role != entity.InterfaceRolePrivate {
				t.Fatal("stdio credential revocation changed the paired tenant")
			}
		})
	}
}
