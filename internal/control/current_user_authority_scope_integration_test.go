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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestCurrentUserAuthorityScopeUsesOneConnectionAndForcedTenant(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	tenants := []string{freshTenant(t, db, "report-authority-a"), freshTenant(t, db, "report-authority-b")}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	users, roles := map[string]string{}, map[string]string{}
	permissions := map[string]string{tenants[0]: permFlowRead, tenants[1]: permTagsRead}
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), db.Pool(), fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "scope@"+tenant+".invalid", "Scope owner")
			if err != nil {
				return err
			}
			users[tenant] = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "same-source-role", "Scoped source", "Current scoped user proof")
			if err != nil {
				return err
			}
			roles[tenant] = role.ID
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permissions[tenant]); err != nil {
				return err
			}
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
				return err
			}
			_, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "OWN-" + tenant, Enabled: true, Effect: auth.PolicyDeny, Permission: permFlowRead, Resource: map[string]string{"site_label": "denied"}, Priority: 100})
			return err
		})
	}
	configuration := db.Pool().Config().Copy()
	configuration.MaxConns, configuration.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	read := func(tenant string, check func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), 5*time.Second)
		defer cancel()
		if err := tenancy.InTenantReadSnapshot(ctx, pool, check); err != nil {
			t.Fatal("single-connection scoped authority read failed", err)
		}
	}
	for lane, tenant := range tenants {
		read(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			authority, err := readCurrentUserAuthorityScope(ctx, sc, users[tenant])
			if err != nil {
				return err
			}
			if authority.principal.TenantID != tenant || authority.principal.UserID != users[tenant] || !authority.principal.Permissions[permissions[tenant]] || authority.principal.Permissions[permissions[tenants[1-lane]]] || authority.principal.MFASatisfied || len(authority.policies) != 1 || authority.policies[0].Name != "OWN-"+tenant {
				t.Fatal("scoped authority borrowed another tenant's user/grant/policy or stored MFA")
			}
			if value, err := readCurrentUserAuthorityScope(ctx, sc, users[tenants[1-lane]]); err == nil || value != nil {
				t.Fatal("predicate-free user lookup escaped forced tenant isolation")
			}
			wrong := sc
			wrong.Tenant = tenancy.ID(tenants[1-lane])
			if value, err := readCurrentUserAuthorityScope(ctx, wrong, users[tenant]); err == nil || value != nil {
				t.Fatal("declared scope could disagree with its bound query context")
			}
			if value, err := readCurrentUserAuthorityScope(t.Context(), sc, users[tenant]); err == nil || value != nil {
				t.Fatal("unbound scoped authority read succeeded")
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if value, err := readCurrentUserAuthorityScope(canceled, sc, users[tenant]); err == nil || value != nil {
				t.Fatal("canceled scoped authority returned partial user state")
			}
			return nil
		})
	}
	red := tenants[0]
	mutate(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, red, roles[red], permFlowRead)
		return err
	})
	read(red, func(ctx context.Context, sc tenancy.Scope) error {
		value, err := readCurrentUserAuthorityScope(ctx, sc, users[red])
		if err != nil {
			return err
		}
		if value.principal.Permissions[permFlowRead] {
			t.Fatal("scoped authority cached a revoked grant")
		}
		return nil
	})
	mutate(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, red, users[red])
		return err
	})
	read(red, func(ctx context.Context, sc tenancy.Scope) error {
		if value, err := readCurrentUserAuthorityScope(ctx, sc, users[red]); err == nil || value != nil {
			t.Fatal("inactive current subject retained scoped authority")
		}
		return nil
	})
}
