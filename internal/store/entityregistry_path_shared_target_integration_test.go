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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSharedPathTargetKeepsOneContextConcurrentWritersAndCleanup(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	registry := NewEntityRegistry(pool)
	var tenants []string
	contexts := []string{uuid.NewString(), uuid.NewString()}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	in := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	bind := func(tenant, id, area string) error {
		return in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return registry.AssignPathTestContext(ctx, sc, id, area)
		})
	}
	concurrent := func(tenant string, tests, areas []string) []error {
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, len(tests))
		for i := range tests {
			wg.Add(1)
			go func(i int) { defer wg.Done(); <-start; results[i] = bind(tenant, tests[i], areas[i]) }(i)
		}
		close(start)
		wg.Wait()
		return results
	}
	check := func(tenant, target string, wantBindings, wantContexts, wantParents int) {
		t.Helper()
		if err := in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var bindings, areas, parents, dangling int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(DISTINCT context_id) FROM entity_path_test_contexts WHERE tenant_id=$1 AND path_target=$2`, tenant, target).Scan(&bindings, &areas); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_path_targets WHERE tenant_id=$1 AND path_target=$2`, tenant, target).Scan(&parents); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_path_test_contexts child LEFT JOIN entity_path_targets parent ON (parent.tenant_id,parent.path_target,parent.context_id)=(child.tenant_id,child.path_target,child.context_id) WHERE child.tenant_id=$1 AND child.path_target=$2 AND parent.tenant_id IS NULL`, tenant, target).Scan(&dangling); err != nil {
				return err
			}
			if bindings != wantBindings || areas != wantContexts || parents != wantParents || dangling != 0 {
				return fmt.Errorf("target guard population=%d contexts=%d anchors=%d dangling=%d; wanted=%d/%d/%d", bindings, areas, parents, dangling, wantBindings, wantContexts, wantParents)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for lane := range 2 {
		ids := make([]string, 7)
		for i := range ids {
			ids[i] = uuid.NewString()
		}
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("shared-path-%d-%d", lane, time.Now().UnixNano()), "Shared path target")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		if err := in(tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			for i, area := range contexts {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,$5,$6)`, tenant.ID, area, uuid.NewString(), uuid.NewString(), fmt.Sprintf("site-%d", i), fmt.Sprintf("VRF-%d", i)); err != nil {
					return err
				}
			}
			for i, id := range ids {
				target := "192.0.2.1"
				if i == 3 || i == 4 {
					target = "192.0.2.2"
				}
				if i == 5 || i == 6 {
					target = "192.0.2.3"
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,enabled) VALUES($1,$2,$3,'icmp',$4,true)`, tenant.ID, id, "shared target "+id, target); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, id := range ids[:2] {
			if err := bind(tenant.ID, id, contexts[0]); err != nil {
				t.Fatal("same-context tests could not share a destination", err)
			}
		}
		check(tenant.ID, "192.0.2.1", 2, 1, 1)
		err = bind(tenant.ID, ids[2], contexts[1])
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23505" || constraint.ConstraintName != "entity_path_target_one_context" {
			t.Fatal("second context did not fail on the destination authority guard", err)
		}
		check(tenant.ID, "192.0.2.1", 2, 1, 1)
		errorsByWriter := concurrent(tenant.ID, ids[3:5], contexts)
		successes := 0
		for _, err := range errorsByWriter {
			if err == nil {
				successes++
				continue
			}
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || !((constraint.Code == "23505" && constraint.ConstraintName == "entity_path_target_one_context") ||
				(constraint.Code == "23503" && constraint.ConstraintName == "entity_path_test_target_context_fk") || constraint.Code == "40001" || constraint.Code == "40P01") {
				t.Fatal("conflicting writer failed for an unrelated reason", err)
			}
		}
		if successes != 1 {
			t.Fatal("concurrent contexts both committed or both failed", successes, errorsByWriter)
		}
		check(tenant.ID, "192.0.2.2", 1, 1, 1)
		for _, err := range concurrent(tenant.ID, ids[5:7], []string{contexts[0], contexts[0]}) {
			if err != nil {
				t.Fatal("concurrent same-context tests were refused", err)
			}
		}
		check(tenant.ID, "192.0.2.3", 2, 1, 1)
		if err := in(tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM tests WHERE tenant_id=$1 AND id=$2`, tenant.ID, ids[0])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		check(tenant.ID, "192.0.2.1", 1, 1, 1)
		if err := in(tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM tests WHERE tenant_id=$1 AND id=$2`, tenant.ID, ids[1])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		check(tenant.ID, "192.0.2.1", 0, 0, 0)
		if err := bind(tenant.ID, ids[2], contexts[1]); err != nil {
			t.Fatal("unused destination anchor blocked explicit reassignment", err)
		}
		check(tenant.ID, "192.0.2.1", 1, 1, 1)
	}
	// Reused canonical context UUIDs and identical destination strings in the
	// sibling tenant never select its rows or context from this app-role scope.
	check(tenants[0], "192.0.2.1", 1, 1, 1)
	check(tenants[1], "192.0.2.1", 1, 1, 1)
	t.Log("real-integration: repeated target/context UUIDs in paired app-role PG/RLS, concurrent same/conflicting context writers, per-test deletion, anchor cleanup and explicit reassignment; no network observation claim")
}
