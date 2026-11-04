// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// currentUserAuthority is a request-local current user/role/policy read, never
// delegated session or MFA authority. The tenant registry uses its existing
// restricted lifecycle door; tenant-owned records use the application RLS lane.
type currentUserAuthority struct {
	principal *auth.Principal
	policies  []auth.Policy
}

func loadCurrentUserAuthority(ctx context.Context, pool *pgxpool.Pool, tenantID, userID string) (*currentUserAuthority, error) {
	bound, ok := tenancy.FromContext(ctx)
	if pool == nil || !ok || bound.String() != tenantID || userID == "" {
		return nil, apierror.Forbidden("current metadata user is unavailable")
	}
	status, err := NewTenantStatusCache(pool, 0).TenantStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, apierror.Forbidden("current metadata tenant is inactive")
	}
	var out *currentUserAuthority
	err = tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		out, readErr = readCurrentUserAuthorityScope(ctx, sc, userID)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The caller owns the active-tenant/lifecycle guard and writer fence. This
// reads only current subject state through an already bound RLS scope; it
// never acquires a pool connection or replaces actual credential authority.
func readCurrentUserAuthorityScope(ctx context.Context, sc tenancy.Scope, userID string) (*currentUserAuthority, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || sc.Q == nil || bound != sc.Tenant || sc.Tenant.String() == "" || userID == "" {
		return nil, apierror.Forbidden("current metadata user scope is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	user, err := (store.Users{}).Get(ctx, sc, userID)
	if err != nil {
		return nil, err
	}
	if user.TenantID != sc.Tenant.String() || user.Status != "active" {
		return nil, apierror.Forbidden("current metadata user is inactive")
	}
	grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", userID)
	if err != nil {
		return nil, err
	}
	policies, err := (store.ABACPolicies{}).List(ctx, sc)
	if err != nil {
		return nil, err
	}
	return &currentUserAuthority{principal: auth.PrincipalWithPermissionGrants(&auth.Principal{
		TenantID: sc.Tenant.String(), UserID: user.ID, Email: user.Email,
		DisplayName: user.DisplayName, ViaBearerToken: true,
		Attributes: composeSubjectAttributes(user.Attributes, false),
	}, grants), policies: policies}, nil
}

type loadedUserAuthorizationKey struct{}

// The actual credential remains a separate ceiling. Both this principal and
// the supplied current principal must pass the single authorization door.
type loadedUserAuthorization struct {
	tenantID, userID string
	current          *auth.Principal
	ceiling          *auth.Principal
	policies         []auth.Policy
}

func (a *currentUserAuthority) requestContext(ctx context.Context, actor *auth.Principal) (context.Context, *auth.Principal, error) {
	if a == nil || a.principal == nil || actor == nil || actor.UserID == "" ||
		actor.TenantID != a.principal.TenantID || actor.UserID != a.principal.UserID {
		return nil, nil, apierror.Forbidden("current user and credential identities do not match")
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != actor.TenantID {
		return nil, nil, apierror.Forbidden("current user tenant scope is unavailable")
	}
	current := auth.ClonePrincipal(a.principal)
	current.MFASatisfied = actor.MFASatisfied
	current.ViaBearerToken = actor.ViaBearerToken
	current.Attributes = composeSubjectAttributes(current.Attributes, actor.MFASatisfied)
	ceiling := auth.ClonePrincipal(actor)
	ceiling.Email = current.Email
	ceiling.DisplayName = current.DisplayName
	ceiling.Attributes = composeSubjectAttributes(a.principal.Attributes, actor.MFASatisfied)
	policies := append([]auth.Policy(nil), a.policies...)
	for i := range policies {
		policies[i].Subject = maps.Clone(policies[i].Subject)
		policies[i].Resource = maps.Clone(policies[i].Resource)
	}
	loaded := &loadedUserAuthorization{tenantID: actor.TenantID, userID: actor.UserID,
		current: auth.ClonePrincipal(current), ceiling: ceiling, policies: policies}
	ctx = context.WithValue(ctx, loadedUserAuthorizationKey{}, loaded)
	return auth.WithPrincipal(ctx, current), current, nil
}

func (a *currentUserAuthority) backgroundContext(ctx context.Context, permissions []string) (context.Context, *auth.Principal, error) {
	if a == nil || a.principal == nil || len(permissions) == 0 {
		return nil, nil, apierror.Forbidden("current background source user is unavailable")
	}
	for _, permission := range permissions {
		if permission != permAIQuery && !isReadPermission(permission) {
			return nil, nil, apierror.Forbidden("background source delegation is read-only")
		}
	}
	principal := narrowPrincipalToScopes(auth.ClonePrincipal(a.principal), permissions)
	principal.MFASatisfied = false
	principal.ViaBearerToken = true
	principal.Attributes = composeSubjectAttributes(principal.Attributes, false)
	ctx, _, err := a.requestContext(ctx, principal)
	if err != nil {
		return nil, nil, err
	}
	return auth.WithPrincipal(ctx, principal), principal, nil
}
