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
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPathContextBindingRequiresSameTenantTestAndContext(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "path-context-a-"+suffix, "Path Context A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "path-context-b-"+suffix, "Path Context B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove path-context tenants: %v", err)
		}
	}()
	repo := NewEntityRegistry(pool)
	testIDs := map[string]string{}
	contexts := map[string]string{}
	for _, tenant := range []string{a.ID, b.ID} {
		testIDs[tenant] = uuid.NewString()
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target)
				VALUES ($1,$2,$3,'10.42.0.1')`, tenant, testIDs[tenant], "path-"+tenant); err != nil {
				return err
			}
			scope, err := repo.CreateEntityContext(ctx, sc, "West DC", "Customer A")
			if err == nil {
				contexts[tenant] = scope.ContextID
			}
			return err
		})
	}
	ctxA := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	if _, err := repo.PathTestContext(ctxA, a.ID, testIDs[a.ID]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unbound test context = %v, want no row", err)
	}
	for name, pair := range map[string]struct{ test, context string }{
		"other tenant test":    {testIDs[b.ID], contexts[a.ID]},
		"other tenant context": {testIDs[a.ID], contexts[b.ID]},
	} {
		writeErr := tenancy.InTenant(ctxA, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return repo.AssignPathTestContext(ctx, sc, pair.test, pair.context)
		})
		if writeErr == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, testIDs[a.ID], contexts[a.ID])
	})
	got, err := repo.PathTestContext(ctxA, a.ID, testIDs[a.ID])
	if err != nil || got.ContextID != contexts[a.ID] || got.TenantID != a.ID {
		t.Fatalf("own path context = %+v, %v", got, err)
	}
	binding, err := repo.PathTestBinding(ctxA, a.ID, testIDs[a.ID])
	if err != nil || binding.Scope != got || binding.Target != "10.42.0.1" || binding.AssignedAt.IsZero() {
		t.Fatalf("own binding must include its destination and assignment time: %+v, %v", binding, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, testIDs[a.ID], contexts[a.ID])
	})
	repeated, err := repo.PathTestBinding(ctxA, a.ID, testIDs[a.ID])
	if err != nil || !repeated.AssignedAt.Equal(binding.AssignedAt) {
		t.Fatalf("unchanged binding restarted discovery authority: %+v, %v", repeated, err)
	}
	// Path rounds are stored by tenant+normalized destination, not test ID.
	// A URL-shaped second test to the same host cannot use a different VRF.
	secondTestID := uuid.NewString()
	var secondContextID string
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target)
			VALUES ($1,$2,'path-second','https://10.42.0.1:443/health')`,
			a.ID, secondTestID); err != nil {
			return err
		}
		second, err := repo.CreateEntityContext(ctx, sc, "West DC", "Customer B")
		if err != nil {
			return err
		}
		secondContextID = second.ContextID
		return nil
	})
	if err := tenancy.InTenant(ctxA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, secondTestID, secondContextID)
	}); err == nil {
		t.Fatal("two routing contexts claimed the same tenant path destination")
	}
	// Editing the first test invalidates its old binding until the operator
	// deliberately reassigns it, releasing the old destination for test two.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tests SET target='10.42.0.2'
			WHERE tenant_id=$1 AND id=$2`, a.ID, testIDs[a.ID])
		return err
	})
	if _, err := repo.PathTestContext(ctxA, a.ID, testIDs[a.ID]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("edited target retained stale routing context: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var stale int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_path_test_contexts
			WHERE tenant_id=$1 AND test_id=$2`, a.ID, testIDs[a.ID]).Scan(&stale); err != nil {
			return err
		}
		if stale != 0 {
			t.Fatal("target edit left an old destination binding in storage")
		}
		return nil
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, testIDs[a.ID], contexts[a.ID])
	})
	retargeted, err := repo.PathTestBinding(ctxA, a.ID, testIDs[a.ID])
	if err != nil || retargeted.Target != "10.42.0.2" || !retargeted.AssignedAt.After(binding.AssignedAt) {
		t.Fatalf("retargeted binding reused old path destination or time: %+v, %v", retargeted, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, secondTestID, secondContextID)
	})
	if got, err := repo.PathTestContext(ctxA, a.ID, secondTestID); err != nil ||
		got.ContextID != secondContextID {
		t.Fatalf("freed path destination did not bind: %+v err=%v", got, err)
	}
	if _, err := repo.PathTestContext(ctxA, b.ID, testIDs[b.ID]); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("foreign tenant read = %v, want scope mismatch", err)
	}
	if _, err := repo.PathTestContext(ctxA, a.ID, testIDs[b.ID]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign test read = %v, want no row", err)
	}
	// An explicit context rebind must move both bindings together and remove
	// the old context's test assignment, rather than carrying metadata across.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var tagID string
		if err := sc.Q.QueryRow(ctx, `INSERT INTO tenant_tag_definitions (tenant_id,id,key)
			VALUES ($1,gen_random_uuid(),'path_context') RETURNING id::text`, a.ID).Scan(&tagID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments
			(tenant_id,context_id,id,tag_id,target_kind,test_id,value,source)
			VALUES ($1,$2,gen_random_uuid(),$3,'test',$4,'old_context','manual')`, a.ID, contexts[a.ID], tagID, testIDs[a.ID])
		return err
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignPathTestContext(ctx, sc, testIDs[a.ID], secondContextID)
	})
	rebound, err := repo.PathTestBinding(ctxA, a.ID, testIDs[a.ID])
	if err != nil || rebound.Scope.ContextID != secondContextID || !rebound.AssignedAt.After(retargeted.AssignedAt) {
		t.Fatalf("context rebind did not renew path authority: %+v, %v", rebound, err)
	}
	var generalContext string
	var staleAssignments int
	if err := pool.QueryRow(ctx, `SELECT context_id::text FROM entity_test_contexts WHERE tenant_id=$1 AND test_id=$2`, a.ID, testIDs[a.ID]).Scan(&generalContext); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=$1 AND test_id=$2`, a.ID, testIDs[a.ID]).Scan(&staleAssignments); err != nil {
		t.Fatal(err)
	}
	if generalContext != secondContextID || staleAssignments != 0 {
		t.Fatal("general/path context diverged or stale tag assignment survived rebind")
	}
}
