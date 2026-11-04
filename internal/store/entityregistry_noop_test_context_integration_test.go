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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTargetlessNoopTagContextIsolationKeepsPathAuthorityAbsent(t *testing.T) {
	t.Run("success", proveTargetlessNoopTagContext)
}

func proveTargetlessNoopTagContext(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("owned noop test fixture cleanup failed")
		}
	})
	type lane struct {
		tenant, context, noop, secondNoop, path, tag string
	}
	lanes := make([]lane, 2)
	repo := NewEntityRegistry(pool)
	for i := range lanes {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("noop-test-context-%d-%d", i, time.Now().UnixNano()), "Noop test context")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		l := &lanes[i]
		l.tenant, l.noop, l.secondNoop, l.path = tenant.ID, uuid.NewString(), uuid.NewString(), uuid.NewString()
		bound := tenancy.WithTenant(ctx, tenancy.ID(l.tenant))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			context, err := repo.CreateEntityContext(ctx, sc, "same site", "same VRF")
			if err != nil {
				return err
			}
			l.context = context.ContextID
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target) VALUES
				($1,$2,'same-targetless','noop',''),($1,$3,'same-targetless','noop',''),
				($1,$4,'network test','http','https://192.0.2.10/health')`, l.tenant, l.noop, l.secondNoop, l.path); err != nil {
				return err
			}
			definition, err := (TagDefinitions{}).Create(ctx, sc, "noop_customer")
			if err != nil {
				return err
			}
			l.tag = definition.ID
			_, err = (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: l.tenant, ContextID: l.context}, TagID: l.tag,
				TargetKind: "test", Match: "name_pattern", NamePattern: "^same-targetless$", Value: "own-" + l.tenant})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		// Establish a normal network binding before the targetless case. Its
		// destination and authority remain unchanged by metadata-only writes.
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return repo.AssignPathTestContext(ctx, sc, l.path, l.context)
		}); err != nil {
			t.Fatal("normal path context prerequisite failed", err)
		}
		if binding, err := repo.PathTestBinding(bound, l.tenant, l.path); err != nil || binding.Target != "192.0.2.10" {
			t.Fatal("normal path binding lost its destination prerequisite", err)
		}
		for _, id := range []string{l.noop, l.secondNoop} {
			if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
				return repo.AssignPathTestContext(ctx, sc, id, l.context)
			}); err != nil {
				t.Fatal("owned targetless noop context was refused", err)
			}
			if _, err := repo.PathTestBinding(bound, l.tenant, id); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("targetless noop acquired path authority", err)
			}
		}
	}
	for i, l := range lanes {
		foreign := lanes[1-i]
		bound := tenancy.WithTenant(ctx, tenancy.ID(l.tenant))
		for _, attempt := range []struct{ test, context string }{{foreign.noop, l.context}, {l.noop, foreign.context}} {
			if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
				return repo.AssignPathTestContext(ctx, sc, attempt.test, attempt.context)
			}); err == nil {
				t.Fatal("foreign targetless test/context acquired a binding")
			}
		}
		snapshot, err := NewTagSnapshots(pool).LoadTests(bound, []string{l.noop, l.secondNoop, foreign.noop}, 2<<20)
		if err != nil {
			t.Fatal("owned targetless test metadata snapshot failed", err)
		}
		for _, id := range []string{l.noop, l.secondNoop} {
			item, err := snapshot.ResolveContext(bound, l.tenant, id, map[string]bool{l.context: true}, 2<<20)
			if err != nil || item == nil || item.Scope.TenantID != l.tenant || item.Scope.ContextID != l.context || len(item.Items) != 1 || item.Items[0].TagID != l.tag || item.Items[0].Value != "own-"+l.tenant {
				t.Fatal("targetless test tag rule lost owned identity after foreign refusals", err)
			}
		}
		if item, err := snapshot.ResolveContext(bound, l.tenant, foreign.noop, map[string]bool{l.context: true}, 2<<20); err != nil || item != nil {
			t.Fatal("foreign targetless test disclosed metadata", err)
		}
		// A previously network-targeted noop must also lose the old path row
		// when explicitly rebound after its target becomes empty.
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `UPDATE tests SET target='192.0.2.77' WHERE tenant_id=$1 AND id=$2`, l.tenant, l.noop); err != nil {
				return err
			}
			if err := repo.AssignPathTestContext(ctx, sc, l.noop, l.context); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE tests SET target='' WHERE tenant_id=$1 AND id=$2`, l.tenant, l.noop); err != nil {
				return err
			}
			if err := repo.AssignPathTestContext(ctx, sc, l.noop, l.context); err != nil {
				return err
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_path_test_contexts WHERE tenant_id=$1 AND test_id=ANY($2::uuid[])`, l.tenant, []string{l.noop, l.secondNoop}).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("metadata-only rebinding retained an old path row")
			}
			invalid := uuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target) VALUES ($1,$2,'invalid network fixture','http','')`, l.tenant, invalid); err != nil {
				return err
			}
			if err := repo.AssignPathTestContext(ctx, sc, invalid, l.context); !errors.Is(err, entity.ErrInvalidClaim) {
				t.Fatal("empty network target escaped the existing invalid-claim refusal", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
