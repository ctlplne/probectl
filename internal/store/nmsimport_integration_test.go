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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestNMSImportStorageIsolation proves that an import plan cannot point at a
// source, row target or provenance entity in another tenant or routing
// context. The same private address and external key may exist in both lanes.
func TestNMSImportStorageIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "import-a-"+suffix, "Import A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "import-b-"+suffix, "Import B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove import fixture tenants: %v", err)
		}
	})
	contextA, contextOther := uuid.NewString(), uuid.NewString()
	entityA, entityOther, entityB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	seed := func(tenant, routingContext, entityID string) {
		t.Helper()
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`, tenant, routingContext,
				uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label)
				VALUES ($1,$2,$3,'device','router')`, tenant, routingContext, entityID)
			return err
		})
	}
	seed(a.ID, contextA, entityA)
	seed(a.ID, contextOther, entityOther)
	seed(b.ID, contextA, entityB)
	sourceA, planA := uuid.NewString(), uuid.NewString()
	sourceB, planB := uuid.NewString(), uuid.NewString()
	seedPlan := func(tenant, routingContext, sourceID, planID string) {
		t.Helper()
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_sources
				(tenant_id,context_id,id,source_kind,instance_ref)
				VALUES ($1,$2,$3,'librenms','lab')`, tenant, routingContext, sourceID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_plans
				(tenant_id,context_id,id,source_id,snapshot_hash,source_generation_hash,
				 policy_version,row_count,expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,1,1,clock_timestamp()+interval '1 hour')`,
				tenant, routingContext, planID, sourceID,
				strings.Repeat("a", 64), strings.Repeat("b", 64))
			return err
		})
	}
	seedPlan(a.ID, contextA, sourceA, planA)
	seedPlan(b.ID, contextA, sourceB, planB)
	tryA := func(sql string, args ...any) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, sql, args...)
				return err
			})
	}
	if err := tryA(`INSERT INTO nms_import_pages
		(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
		VALUES ($1,$2,$3,0,'devices',0,1,$4)`,
		a.ID, contextA, planB, strings.Repeat("c", 64)); err == nil {
		t.Fatal("capture page accepted another tenant's plan")
	}
	if err := tryA(`INSERT INTO nms_import_pages
		(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
		VALUES ($1,$2,$3,0,'devices',0,1,$4)`,
		a.ID, contextA, planA, strings.Repeat("c", 64)); err != nil {
		t.Fatalf("own capture page: %v", err)
	}
	if err := tryA(`INSERT INTO nms_import_pages
		(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
		VALUES ($1,$2,$3,0,'devices',0,1,$4)`,
		a.ID, contextA, planA, strings.Repeat("d", 64)); err == nil {
		t.Fatal("duplicate capture page replaced its original hash")
	}
	if err := tryA(`INSERT INTO nms_import_sources
		(tenant_id,context_id,id,source_kind,instance_ref)
		VALUES ($1,$2,$3,'librenms','https://nms/?token=secret')`,
		a.ID, contextA, uuid.NewString()); err == nil {
		t.Fatal("source instance accepted a credential-shaped URL")
	}
	for name, target := range map[string]string{
		"other routing context": entityOther,
		"other tenant":          entityB,
	} {
		if err := tryA(`INSERT INTO nms_import_rows
			(tenant_id,context_id,plan_id,row_number,object_kind,external_id,
			 address,target_entity_id,action)
			VALUES ($1,$2,$3,0,'device','17','10.42.0.1',$4,'update')`,
			a.ID, contextA, planA, target); err == nil {
			t.Fatalf("plan row accepted %s entity", name)
		}
	}
	if err := tryA(`INSERT INTO nms_import_rows
		(tenant_id,context_id,plan_id,row_number,object_kind,external_id,
		 address,target_entity_id,action)
		VALUES ($1,$2,$3,0,'device','17','10.42.0.1',$4,'update')`,
		a.ID, contextA, planA, entityA); err != nil {
		t.Fatalf("own plan row: %v", err)
	}
	if err := tryA(`INSERT INTO nms_import_provenance
		(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
		VALUES ($1,$2,$3,'device','18',$4,$5)`,
		a.ID, contextA, sourceA, entityA, planA); err == nil {
		t.Fatal("provenance accepted an absent plan row")
	}
	for _, tc := range []struct {
		name, source, plan, entity string
	}{
		{"foreign plan", sourceA, planB, entityA},
		{"foreign source", sourceB, planA, entityA},
		{"foreign context entity", sourceA, planA, entityOther},
		{"foreign tenant entity", sourceA, planA, entityB},
	} {
		if err := tryA(`INSERT INTO nms_import_provenance
			(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
			VALUES ($1,$2,$3,'device','17',$4,$5)`,
			a.ID, contextA, tc.source, tc.entity, tc.plan); err == nil {
			t.Fatalf("provenance accepted %s", tc.name)
		}
	}
	if err := tryA(`INSERT INTO nms_import_provenance
		(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
		VALUES ($1,$2,$3,'device','17',$4,$5)`,
		a.ID, contextA, sourceA, entityA, planA); err != nil {
		t.Fatalf("own provenance: %v", err)
	}
	if err := tryA(`DELETE FROM nms_import_plans
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextA, planA); err == nil {
		t.Fatal("applied provenance was erased by deleting its plan")
	}
	for _, table := range []string{"nms_import_sources", "nms_import_plans", "nms_import_pages", "nms_import_rows", "nms_import_provenance"} {
		inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
			var n int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, a.ID).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Fatalf("tenant B read %d tenant A %s rows", n, table)
			}
			return nil
		})
	}
}
