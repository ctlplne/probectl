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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// FX-3 state is shared-schema in pooled mode. The application role must see
// exactly its tenant's definitions and assignments, even when IDs and labels
// collide; a foreign row must be rejected before a handler can inspect it.
func TestTagPooledRLSAndTypedAssignmentRejectForeignTenant(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-pooled-a-"+suffix, "Tag pooled A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-pooled-b-"+suffix, "Tag pooled B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove pooled tag fixture: %v", err)
		}
	})
	contextA, contextB := uuid.NewString(), uuid.NewString()
	entityID, tagID := uuid.NewString(), uuid.NewString()
	for _, row := range []struct{ tenant, routingContext string }{
		{a.ID, contextA}, {b.ID, contextB},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
			row.tenant, row.routingContext, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','same-edge')`,
			row.tenant, row.routingContext, entityID); err != nil {
			t.Fatal(err)
		}
	}
	appExec := func(caller, sql string, args ...any) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for _, tenant := range []string{a.ID, b.ID} {
		if err := appExec(tenant, `INSERT INTO tenant_tag_definitions
			(tenant_id,id,key) VALUES ($1,$2,'customer')`, tenant, tagID); err != nil {
			t.Fatalf("own definition: %v", err)
		}
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
			WHERE tenant_id=$1`, tenant).Scan(&revision); err != nil || revision != 2 {
			t.Fatalf("first accepted tag write must move baseline revision 1 to 2: %d, %v", revision, err)
		}
	}
	insert := `INSERT INTO tenant_tag_assignments
		(tenant_id,context_id,id,tag_id,target_kind,entity_id,entity_kind,value,source)
		VALUES ($1,$2,$3,$4,'device',$5,'device','tenant-value','manual')`
	if err := appExec(a.ID, insert, a.ID, contextA, uuid.NewString(), tagID, entityID); err != nil {
		t.Fatalf("own assignment: %v", err)
	}
	if err := appExec(a.ID, insert, b.ID, contextB, uuid.NewString(), tagID, entityID); err == nil {
		t.Fatal("tenant A wrote tenant B's assignment")
	}
	if err := appExec(a.ID, insert, a.ID, contextB, uuid.NewString(), tagID, entityID); err == nil {
		t.Fatal("tenant A attached its tag to tenant B's routing context")
	}
	for _, tc := range []struct {
		caller string
		want   int
	}{{a.ID, 1}, {b.ID, 0}} {
		got := countVisibleTagAssignments(ctx, t, pool, tc.caller)
		if got != tc.want {
			t.Fatalf("caller %s saw %d assignments, want %d", tc.caller, got, tc.want)
		}
	}
	if got := countVisibleTagAssignments(ctx, t, pool, ""); got != 0 {
		t.Fatalf("missing tenant scope saw %d assignments", got)
	}
	scopeA := tags.Scope{TenantID: a.ID, ContextID: contextA}
	ownedCtx := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	loaded, err := loadContextTagSnapshotForTest(ownedCtx, pool, scopeA, 1<<20)
	if err != nil {
		t.Fatalf("load bounded owned tag snapshot: %v", err)
	}
	if revision, err := loaded.Revision(); err != nil || revision != 3 {
		t.Fatalf("stored snapshot did not pin definition and assignment revision 3: %d, %v", revision, err)
	}
	resolved, err := loaded.Resolve(tags.Subject{Scope: scopeA, Kind: "device", ID: entityID})
	if err != nil || len(resolved) != 1 || resolved[0].Value != "tenant-value" {
		t.Fatalf("stored tag was not resolved for its owned entity: %+v, %v", resolved, err)
	}
	if _, err := loadContextTagSnapshotForTest(ownedCtx, pool, scopeA, 512); !errors.Is(err, ErrTagSnapshotBudget) {
		t.Fatalf("small query memory budget admitted an oversized snapshot: %v", err)
	}
	if _, err := loadContextTagSnapshotForTest(tenancy.WithTenant(ctx, tenancy.ID(b.ID)), pool, scopeA, 1<<20); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatalf("foreign caller loaded tenant A's tag snapshot: %v", err)
	}
	if _, err := loadContextTagSnapshotForTest(ownedCtx, pool, tags.Scope{TenantID: a.ID, ContextID: contextB},
		1<<20); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatalf("tenant A loaded an unowned routing context: %v", err)
	}
	// A page and its tag snapshot must keep one committed vocabulary/revision
	// even when a separate operator transaction edits a key mid-read.
	snapshotCtx := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	err = tenancy.InTenantReadSnapshot(snapshotCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if !tenancy.SiloTableLockContext(ctx) {
			t.Fatal("multi-statement tag read did not request the silo table lock")
		}
		var keyBefore, keyAfter string
		var revisionBefore, revisionAfter int64
		read := func(key *string, revision *int64) error {
			return sc.Q.QueryRow(ctx, `SELECT d.key,r.revision
				FROM tenant_tag_definitions d
				JOIN tenant_tag_revisions r ON r.tenant_id=d.tenant_id
				WHERE d.tenant_id=$1 AND d.id=$2`, a.ID, tagID).
				Scan(key, revision)
		}
		if err := read(&keyBefore, &revisionBefore); err != nil {
			return err
		}
		if err := appExec(a.ID, `UPDATE tenant_tag_definitions SET key='customer_new'
			WHERE tenant_id=$1 AND id=$2`, a.ID, tagID); err != nil {
			return err
		}
		if err := read(&keyAfter, &revisionAfter); err != nil {
			return err
		}
		if keyBefore != "customer" || keyAfter != keyBefore || revisionAfter != revisionBefore {
			t.Fatalf("read snapshot mixed two tag revisions: %q/%d then %q/%d",
				keyBefore, revisionBefore, keyAfter, revisionAfter)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tenant read snapshot: %v", err)
	}
	var latestKey string
	if err := pool.QueryRow(ctx, `SELECT key FROM tenant_tag_definitions
		WHERE tenant_id=$1 AND id=$2`, a.ID, tagID).Scan(&latestKey); err != nil || latestKey != "customer_new" {
		t.Fatalf("new transaction did not see committed tag edit: %q, %v", latestKey, err)
	}
}

func countVisibleTagAssignments(ctx context.Context, t *testing.T, pool *pgxpool.Pool, caller string) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatal(err)
	}
	if caller != "" {
		if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_assignments`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// Exercise the same context loader used by tenant-wide shipping queries, with
// one real RLS snapshot and a caller-owned byte budget.
func loadContextTagSnapshotForTest(ctx context.Context, pool *pgxpool.Pool, scope tags.Scope, maxBytes int64) (*tags.Snapshot, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != scope.TenantID {
		return nil, tags.ErrScopeMismatch
	}
	var result *tags.Snapshot
	err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var revision int64
		if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1`, scope.TenantID).Scan(&revision); err != nil {
			return err
		}
		used := int64(0)
		charge := func(parts ...string) error {
			used += 2048
			for _, part := range parts {
				used += int64(len(part))
			}
			if used > maxBytes {
				return ErrTagSnapshotBudget
			}
			return nil
		}
		definitions, err := loadTagDefinitions(ctx, sc, scope, charge)
		if err != nil {
			return err
		}
		result, err = loadTagContextSnapshot(ctx, sc, scope, revision, definitions, charge)
		return err
	})
	return result, err
}
