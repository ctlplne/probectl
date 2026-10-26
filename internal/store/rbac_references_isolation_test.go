// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoleBindingReferencesStayInTenant(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	type fixture struct{ tenant, user, service, role, org string }
	fixtures := make([]fixture, 2)
	for i := range fixtures {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("binding-ref-%d-%d", time.Now().UnixNano(), i), "Binding references")
		if err != nil {
			t.Fatal(err)
		}
		f := &fixtures[i]
		f.tenant = tenant.ID
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, s tenancy.Scope) error {
			user, err := (Users{}).Create(ctx, s, "binding@example.test", "Binding user")
			if err != nil {
				return err
			}
			f.user = user.ID
			role, err := (Roles{}).Create(ctx, s, "binding", "Binding", "")
			if err != nil {
				return err
			}
			f.role = role.ID
			org, err := (Organizations{}).Create(ctx, s, "binding", "Binding")
			if err != nil {
				return err
			}
			f.org = org.ID
			return s.Q.QueryRow(ctx, `INSERT INTO service_accounts (tenant_id, name) VALUES ($1, 'binding') RETURNING id::text`, s.Tenant.String()).Scan(&f.service)
		})
	}
	writers := map[string]func(context.Context, tenancy.Scope, string, string, string, string) error{
		"create": func(ctx context.Context, s tenancy.Scope, typ, subject, role, _ string) error {
			_, err := (RoleBindings{}).Create(ctx, s, typ, subject, role, "tenant", nil)
			return err
		},
		"bind": func(ctx context.Context, s tenancy.Scope, typ, subject, role, _ string) error {
			return (RoleBindings{}).Bind(ctx, s, typ, subject, role)
		},
		"scoped": func(ctx context.Context, s tenancy.Scope, typ, subject, role, org string) error {
			return (RoleBindings{}).BindScoped(ctx, s, typ, subject, role, "org", org)
		},
	}
	for i, own := range fixtures {
		foreign := fixtures[1-i]
		for _, name := range []string{"create", "bind", "scoped"} {
			write := writers[name]
			for _, typ := range []string{"user", "service_account"} {
				subject, foreignSubject := own.user, foreign.user
				if typ == "service_account" {
					subject, foreignSubject = own.service, foreign.service
				}
				for _, bad := range []struct{ subject, role string }{{foreignSubject, own.role}, {subject, foreign.role}, {"00000000-0000-0000-0000-000000000099", own.role}} {
					err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(own.tenant)), pool, func(ctx context.Context, s tenancy.Scope) error {
						return write(ctx, s, typ, bad.subject, bad.role, own.org)
					})
					if err == nil {
						t.Fatalf("tenant %d %s %s accepted foreign/missing reference", i, name, typ)
					}
				}
				inTenant(ctx, t, pool, own.tenant, func(ctx context.Context, s tenancy.Scope) error {
					return write(ctx, s, typ, subject, own.role, own.org)
				})
			}
		}
	}
}
