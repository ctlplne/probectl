// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres/FORCE-RLS, current user grants and owned
// source/configuration writers. Public datasets and sender identities are
// synthetic; this does not assert a live IX/session or served estimate.
func TestPeeringTargetStoreKeepsCurrentTenantGrantAndPublicationAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	actors := map[string]*auth.Principal{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAIQuery, permFlowRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			configuration := store.InterfaceRoleConfiguration{}
			policy, err := configuration.Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			if _, err := configuration.PutPolicy(ctx, sc, f.contextID, policy.ID, policy.Revision, entity.InterfaceRolePolicyDefinition{}, roleExplanationStoreBudget()); err != nil {
				return err
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: f.users[tenant], ViaBearerToken: true}, grants)
			return err
		})
	}
	f.server.openDataEnricher = peeringTargetSources(t, time.Now().UTC(), 11, 5001, "10.42.0.0/24")
	budget := interfaceRoleBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20}
	target := func(tenant string) peeringTarget {
		return peeringTarget{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, InterfaceID: f.interfaceID, PeerASN: ^uint32(0), IXID: 71, LANID: 11}
	}
	read := func(tenant string) peeringTargetEligibility {
		t.Helper()
		got, err := f.server.loadPeeringTarget(t.Context(), actors[tenant], target(tenant), budget)
		if err != nil || !got.Eligible || got.Target.Scope.TenantID != tenant || got.RouterID != f.routerID || len(got.PrefixIDs) != 1 || len(got.MembershipIDs) != 5001 {
			t.Fatal("actual peering target lost complete owned source evidence", got, err)
		}
		return got
	}
	a, b := f.tenants[0], f.tenants[1]
	first, second := read(a), read(b)
	if first.InputDigest == second.InputDigest {
		t.Fatal("same-key paired tenant peering targets shared private input identity")
	}
	if got, err := f.server.loadPeeringTarget(t.Context(), actors[a], target(b), budget); err == nil || got.Eligible || got.Target.InterfaceID != "" {
		t.Fatal("actual peering target crossed its outer tenant boundary", got, err)
	}
	if got, err := f.server.loadPeeringTarget(tenancy.WithTenant(t.Context(), tenancy.ID(b)), actors[a], target(a), budget); err == nil || got.Eligible {
		t.Fatal("actual peering target replaced a contradictory tenant scope", got, err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
		return err
	})
	if got, err := f.server.loadPeeringTarget(t.Context(), actors[a], target(a), budget); err == nil || got.Eligible {
		t.Fatal("actual peering target bypassed current source-plane permission", got, err)
	}
	read(b)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "events.read")
	})
	first = read(a)
	f.server.openDataEnricher = peeringTargetSources(t, time.Now().UTC(), 11, 5002, "10.42.0.0/24")
	if got, err := f.server.recheckPeeringTarget(t.Context(), actors[a], first, budget); err == nil || got.Eligible {
		t.Fatal("peering target publication reused a changed complete public generation", got, err)
	}
}
