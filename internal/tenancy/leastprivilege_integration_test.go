// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenancy_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestProviderDomainUnderTheLeastPrivilegeServeLogin is the TEN-01 follow-up's
// regression: since the serve login became NOSUPERUSER NOBYPASSRLS, everything
// that reads the tenant registry or the provider audit stream must assume
// probectl_provider, which the login may SET but never inherits. Every path
// below ran on the bare pool and, outside a superuser login, failed with
// "permission denied": the tenant status check on each request, the registry
// behind strict lanes, alerting and SIEM, and the provider audit chain the
// startup verification and the WORM exporter read.
func TestProviderDomainUnderTheLeastPrivilegeServeLogin(t *testing.T) {
	ctx := context.Background()
	admin := ten02Setup(ctx, t)
	defer admin.Close()

	role := fmt.Sprintf("probectl_rt_leastpriv_%d", time.Now().UnixNano())
	const pw = "leastpriv-pw"
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + pw + `' NOSUPERUSER NOBYPASSRLS`,
		`GRANT probectl_app TO ` + role,
		`GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`,
	} {
		mustExec(ctx, t, admin, stmt)
	}
	u, err := url.Parse(ten02DSN())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, pw)
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	if err := tenancy.AssertLoginRolePosture(ctx, pool, false); err != nil {
		t.Fatalf("the provisioned serve login fails the boot posture: %v", err)
	}
	// The single-profile count may refuse a multi-tenant database; it must not
	// be refused the registry.
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return tenancy.AssertDeploymentProfilePosture(ctx, q, "single", false)
	}); err != nil && strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the single-profile tenant count cannot run as the serve login: %v", err)
	}

	tenants := store.NewTenants(pool)
	slug := fmt.Sprintf("leastpriv-%d", time.Now().UnixNano())
	created, err := tenants.Create(ctx, slug, "Least Privilege")
	if err != nil {
		t.Fatalf("create a tenant in the registry as the serve login: %v", err)
	}
	if list, err := tenants.List(ctx); err != nil || !hasTenant(list, created.ID) {
		t.Fatalf("list the registry as the serve login: %v (found=%v)", err, err == nil && hasTenant(list, created.ID))
	}
	if lanes, err := tenants.BusNamespaceTenants(ctx); err != nil || lanes[tenancy.BusNamespaceFor(slug)] != created.ID {
		t.Fatalf("the strict-lane namespace map as the serve login = %v, %v", lanes, err)
	}
	if _, err := tenants.UpdateStatus(ctx, created.ID, "suspended"); err != nil {
		t.Fatalf("suspend a tenant as the serve login: %v", err)
	}
	if status, err := control.NewTenantStatusCache(pool, time.Millisecond).TenantStatus(ctx, created.ID); err != nil || status != "suspended" {
		t.Fatalf("the per-request tenant status as the serve login = %q, %v", status, err)
	}

	if _, err := audit.ProviderAppend(ctx, pool, "system:leastpriv-test", "leastpriv.probe", created.ID, nil); err != nil {
		t.Fatalf("append to the provider audit stream as the serve login: %v", err)
	}
	head, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil || head < 1 {
		t.Fatalf("read the provider audit head as the serve login = %d, %v", head, err)
	}
	if err := audit.ProviderVerifyFrom(ctx, pool, head-1); err != nil {
		t.Fatalf("verify the provider audit chain as the serve login: %v", err)
	}
	if events, err := audit.ListProvider(ctx, pool, head-1, 10); err != nil || len(events) != 1 {
		t.Fatalf("list the provider audit stream as the serve login = %d events, %v", len(events), err)
	}

	// The bare pool still reads none of it: the provider role is assumed, not
	// inherited.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err == nil {
		t.Fatal("the bare serve pool read the tenant registry")
	}
}

func hasTenant(list []store.Tenant, id string) bool {
	for _, tn := range list {
		if tn.ID == id {
			return true
		}
	}
	return false
}
