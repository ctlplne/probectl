// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagBulkWritesAdvanceEachTenantOnce(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, label := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("tag-bulk-%s-%d", label, time.Now().UnixNano()), "Tag bulk "+label)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Errorf("remove bulk tag tenants: %v", err)
		}
	})
	readRevision := func(tenant string) int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1)`, tenant).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	insert := `INSERT INTO tenant_tag_definitions (tenant_id,id,key)
		SELECT $1,gen_random_uuid(),'bulk_'||n::text FROM generate_series(1,32) n`
	for _, tenant := range tenants {
		if readRevision(tenant) != 1 {
			t.Fatal("new tenant did not start at the empty revision")
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, insert, tenant)
			return err
		}); err != nil {
			t.Fatalf("multirow initial insert failed: %v", err)
		}
		if readRevision(tenant) != 2 {
			t.Fatal("multirow insert did not advance the tenant once")
		}
	}
	a, b := tenants[0], tenants[1]
	for _, statement := range []string{
		`UPDATE tenant_tag_definitions SET key=key||'_updated' WHERE tenant_id=$1`,
		`DELETE FROM tenant_tag_definitions WHERE tenant_id=$1`,
	} {
		before := readRevision(a)
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, statement, a)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if readRevision(a) != before+1 || readRevision(b) != 2 {
			t.Fatal("bulk mutation changed the revision more than once or affected the other tenant")
		}
	}
	before := readRevision(a)
	rollback := errors.New("rollback owned bulk fixture")
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, insert, a); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("bulk rollback returned %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_definitions WHERE tenant_id=$1`, a).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 || readRevision(a) != before || readRevision(b) != 2 {
		t.Fatal("bulk rollback leaked data or a revision change")
	}
}
