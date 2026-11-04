// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func currentAuthorityPrincipal(permissions ...string) *auth.Principal {
	return auth.PrincipalWithPermissionGrants(&auth.Principal{
		TenantID: "tenant-a", UserID: "user-a", Attributes: map[string]string{"department": "operations"},
	}, auth.TenantPermissionGrants(permissions))
}

func TestCurrentAuthorizationIntersectsCredentialAndCurrentGrants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current []string
		actor   []string
		want    auth.DecisionReason
	}{
		{"both", []string{permFlowRead}, []string{permFlowRead}, auth.DecisionAllowed},
		{"credential ceiling", []string{permFlowRead}, []string{permAIQuery}, auth.DecisionRBAC},
		{"current revocation", []string{permAIQuery}, []string{permFlowRead}, auth.DecisionRBAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &currentUserAuthority{principal: currentAuthorityPrincipal(tc.current...)}
			actor := currentAuthorityPrincipal(tc.actor...)
			ctx, principal, err := a.requestContext(tenancy.WithTenant(t.Context(), "tenant-a"), actor)
			if err != nil {
				t.Fatal(err)
			}
			reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal,
				map[string]string{auth.ResourceTenantKey: "tenant-a"})
			if err != nil || reason != tc.want {
				t.Fatalf("current/credential intersection = %v, %v; want %v", reason, err, tc.want)
			}
			if reason, err := (&Server{}).decide(ctx, actor, permFlowRead, auth.RBACGlobal,
				map[string]string{auth.ResourceTenantKey: "tenant-a"}); err != nil || reason != tc.want {
				t.Fatalf("an old actor bypassed captured current roles: %v %v; want %v", reason, err, tc.want)
			}
			principal.Permissions[permFlowRead] = true
			principal.PermissionGrants = auth.TenantPermissionGrants([]string{permFlowRead})
			if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal,
				map[string]string{auth.ResourceTenantKey: "tenant-a"}); err != nil || reason != tc.want {
				t.Fatalf("a mutable caller widened captured authority: %v %v; want %v", reason, err, tc.want)
			}
		})
	}
}

func TestCurrentAuthorizationUsesFreshAttributesAndActualMFA(t *testing.T) {
	a := &currentUserAuthority{principal: currentAuthorityPrincipal(permFlowRead), policies: []auth.Policy{
		{Name: "department", Effect: auth.PolicyDeny, Permission: permFlowRead, Enabled: true, Subject: map[string]string{"department": "suspended"}},
		{Name: "step-up", Effect: auth.PolicyDeny, Permission: permFlowRead, Enabled: true, Subject: map[string]string{"mfa": "false"}},
	}}
	actor := currentAuthorityPrincipal(permFlowRead)
	actor.Attributes["department"] = "stale-directory-value"
	actor.MFASatisfied = true
	ctx, principal, err := a.requestContext(tenancy.WithTenant(t.Context(), "tenant-a"), actor)
	if err != nil {
		t.Fatal(err)
	}
	resource := map[string]string{auth.ResourceTenantKey: "tenant-a"}
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal, resource); err != nil || reason != auth.DecisionAllowed {
		t.Fatalf("actual request MFA/current directory was lost: %v %v", reason, err)
	}
	if principal.Attributes["department"] != "operations" || a.principal.MFASatisfied || principal.ViaBearerToken {
		t.Fatal("fresh attributes or actual credential kind were replaced by stored session authority")
	}
	a.principal.Attributes["department"] = "suspended"
	ctx, principal, err = a.requestContext(tenancy.WithTenant(t.Context(), "tenant-a"), actor)
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal, resource); err != nil || reason != auth.DecisionPolicyDeny {
		t.Fatalf("old actor attributes bypassed current policy: %v %v", reason, err)
	}
}

func TestCurrentAuthorizationBackgroundHasNoWriteOrMFAAuthority(t *testing.T) {
	a := &currentUserAuthority{principal: currentAuthorityPrincipal(permFlowRead, permAIQuery, "metrics.write")}
	a.principal.MFASatisfied = true // Stored state must never supply this assertion.
	ctx, principal, err := a.backgroundContext(tenancy.WithTenant(t.Context(), "tenant-a"), []string{permFlowRead, permAIQuery})
	if err != nil {
		t.Fatal(err)
	}
	if principal.MFASatisfied || principal.Has("metrics.write") || !principal.ViaBearerToken {
		t.Fatal("background source acquired human, write or stored MFA authority")
	}
	resource := map[string]string{auth.ResourceTenantKey: "tenant-a"}
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal, resource); err != nil || reason != auth.DecisionAllowed {
		t.Fatalf("current background source read refused: %v %v", reason, err)
	}
	if _, _, err := a.backgroundContext(tenancy.WithTenant(t.Context(), "tenant-a"), []string{"metrics.write"}); err == nil {
		t.Fatal("background source accepted a write delegation")
	}
	a.policies = []auth.Policy{{Name: "step-up", Effect: auth.PolicyDeny, Permission: permFlowRead, Enabled: true, Subject: map[string]string{"mfa": "false"}}}
	ctx, principal, err = a.backgroundContext(tenancy.WithTenant(t.Context(), "tenant-a"), []string{permFlowRead})
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal, resource); err != nil || reason != auth.DecisionPolicyDeny {
		t.Fatalf("background source borrowed stored MFA: %v %v", reason, err)
	}
}

func TestCurrentAuthorizationSnapshotCannotBorrowAnotherIdentityOrCache(t *testing.T) {
	a := &currentUserAuthority{principal: currentAuthorityPrincipal(permFlowRead)}
	ctx, principal, err := a.requestContext(tenancy.WithTenant(t.Context(), "tenant-a"), currentAuthorityPrincipal(permFlowRead))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s := &Server{abac: &abacCache{load: func(context.Context, string) ([]auth.Policy, error) {
		calls++
		return nil, errors.New("cache must not replace the current snapshot")
	}}}
	resource := map[string]string{auth.ResourceTenantKey: "tenant-a"}
	if reason, err := s.decide(ctx, principal, permFlowRead, auth.RBACGlobal, resource); err != nil || reason != auth.DecisionAllowed || calls != 0 {
		t.Fatalf("fresh snapshot fell back to cache: %v %v calls=%d", reason, err, calls)
	}
	for _, mutate := range []func(*auth.Principal){
		func(p *auth.Principal) { p.UserID = "another-user" },
		func(p *auth.Principal) { p.TenantID = "tenant-b" },
	} {
		other := auth.ClonePrincipal(principal)
		mutate(other)
		if reason, err := s.decide(ctx, other, permFlowRead, auth.RBACGlobal, resource); err == nil || reason != auth.DecisionTenantBoundary {
			t.Fatalf("fresh policy was borrowed by another identity: %v %v", reason, err)
		}
	}
	if _, err := s.decide(tenancy.WithTenant(t.Context(), "tenant-a"), principal, permFlowRead, auth.RBACGlobal, resource); err == nil || calls != 1 {
		t.Fatal("ordinary authorization hid an actual policy-load failure")
	}
	if _, _, err := a.requestContext(tenancy.WithTenant(t.Context(), "tenant-b"), currentAuthorityPrincipal(permFlowRead)); err == nil {
		t.Fatal("current user context crossed the tenant boundary")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.decide(canceled, principal, permFlowRead, auth.RBACGlobal, resource); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled current authorization accepted: %v", err)
	}
}

func TestCurrentAuthorizationKeepsScopedCredentialAndImmutableSnapshot(t *testing.T) {
	a := &currentUserAuthority{principal: currentAuthorityPrincipal(permFlowRead), policies: []auth.Policy{
		{Name: "captured denial", Enabled: true, Effect: auth.PolicyDeny, Permission: permFlowRead, Resource: map[string]string{"region": "restricted"}},
	}}
	actor := auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: "tenant-a", UserID: "user-a"},
		[]auth.PermissionGrant{{Permission: permFlowRead, ScopeType: auth.ScopeProject, ScopeID: "project-a"}})
	ctx, principal, err := a.requestContext(tenancy.WithTenant(t.Context(), "tenant-a"), actor)
	if err != nil {
		t.Fatal(err)
	}
	actor.PermissionGrants = auth.TenantPermissionGrants([]string{permFlowRead})
	actor.Permissions[permFlowRead] = true
	a.policies[0].Resource["region"] = "changed"
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: "tenant-a"}); err != nil || reason != auth.DecisionRBAC {
		t.Fatalf("scoped credential became a tenant-wide read: %v %v", reason, err)
	}
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACPreverified,
		map[string]string{auth.ResourceTenantKey: "tenant-a"}); err != nil || reason != auth.DecisionRBAC {
		t.Fatalf("preverification bypassed the current credential ceiling: %v %v", reason, err)
	}
	// Even a preverified RBAC caller cannot mutate the captured policy away.
	if reason, err := (&Server{}).decide(ctx, principal, permFlowRead, auth.RBACPreverified,
		map[string]string{auth.ResourceTenantKey: "tenant-a", "region": "restricted"}); err != nil || reason != auth.DecisionPolicyDeny {
		t.Fatalf("captured policy aliases mutable input: %v %v", reason, err)
	}
}
