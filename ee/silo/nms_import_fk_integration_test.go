// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestNMSImportSiloForeignKeys uses the migration login so RLS cannot hide a
// missing FK after CREATE TABLE LIKE. A copied silo must reject cross-context
// and cross-tenant target identities even from that privileged connection.
func TestNMSImportSiloForeignKeys(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a := mkTenant(t, pool, "import-silo-a-"+stamp, "siloed", "")
	b := mkTenant(t, pool, "import-silo-b-"+stamp, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tenant := range []string{a, b} {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatalf("provision import silo: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{a, b} {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Errorf("teardown import silo: %v", err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove import silo fixture tenants: %v", err)
		}
	})
	schemaA, schemaB := quoteIdent(SchemaName(a)), quoteIdent(SchemaName(b))
	contextA, contextOther := uuid.NewString(), uuid.NewString()
	entityA, entityOther, entityB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	seedEntity := func(schema, tenant, routingContext, entityID string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`, tenant, routingContext,
			uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','router')`, tenant, routingContext, entityID); err != nil {
			t.Fatal(err)
		}
	}
	seedEntity(schemaA, a, contextA, entityA)
	seedEntity(schemaA, a, contextOther, entityOther)
	seedEntity(schemaB, b, contextA, entityB)
	sourceA, sourceOther, planA := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, source := range []struct{ id, name string }{{sourceA, "lab-a"}, {sourceOther, "lab-b"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_sources
			(tenant_id,context_id,id,source_kind,instance_ref)
			VALUES ($1,$2,$3,'librenms',$4)`, a, contextA, source.id, source.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_plans
		(tenant_id,context_id,id,source_id,snapshot_hash,source_generation_hash,
		 policy_version,row_count,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,1,1,clock_timestamp()+interval '1 hour')`,
		a, contextA, planA, sourceA, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_pages
		(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
		VALUES ($1,$2,$3,0,'devices',0,1,$4)`,
		a, contextOther, planA, strings.Repeat("c", 64)); err == nil {
		t.Fatal("silo page accepted a plan from another routing context")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_pages
		(tenant_id,context_id,plan_id,page_number,resource_kind,first_row,row_count,page_hash)
		VALUES ($1,$2,$3,0,'devices',0,1,$4)`,
		a, contextA, planA, strings.Repeat("c", 64)); err != nil {
		t.Fatalf("silo own capture page: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_capture_steps
		(tenant_id,context_id,plan_id,resource_kind,start_page,end_page,start_row,end_row)
		VALUES ($1,$2,$3,'devices',0,1,0,1)`, a, contextOther, planA); err == nil {
		t.Fatal("silo capture step accepted a plan from another routing context")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_capture_steps
		(tenant_id,context_id,plan_id,resource_kind,start_page,end_page,start_row,end_row)
		VALUES ($1,$2,$3,'devices',0,1,0,1)`, a, contextA, planA); err != nil {
		t.Fatalf("silo own capture step: %v", err)
	}
	for name, entityID := range map[string]string{
		"other context": entityOther,
		"other tenant":  entityB,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_rows
			(tenant_id,context_id,plan_id,row_number,object_kind,external_id,
			 target_entity_id,action,target_fingerprint,reviewed_at)
			VALUES ($1,$2,$3,0,'device','17',$4,'update',$5,clock_timestamp())`,
			a, contextA, planA, entityID, strings.Repeat("d", 64)); err == nil {
			t.Fatalf("silo row accepted %s entity", name)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_rows
		(tenant_id,context_id,plan_id,row_number,object_kind,external_id,
		 target_entity_id,action,target_fingerprint,reviewed_at)
		VALUES ($1,$2,$3,0,'device','17',$4,'update',$5,clock_timestamp())`,
		a, contextA, planA, entityA, strings.Repeat("d", 64)); err != nil {
		t.Fatalf("silo own row: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_provenance
		(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
		VALUES ($1,$2,$3,'device','18',$4,$5)`,
		a, contextA, sourceA, entityA, planA); err == nil {
		t.Fatal("silo provenance accepted an absent plan row")
	}
	for _, tc := range []struct{ name, source, entity string }{
		{"wrong source for plan", sourceOther, entityA},
		{"other context entity", sourceA, entityOther},
		{"other tenant entity", sourceA, entityB},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_provenance
			(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
			VALUES ($1,$2,$3,'device','17',$4,$5)`,
			a, contextA, tc.source, tc.entity, planA); err == nil {
			t.Fatalf("silo provenance accepted %s", tc.name)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.nms_import_provenance
		(tenant_id,context_id,source_id,object_kind,external_id,entity_id,plan_id)
		VALUES ($1,$2,$3,'device','17',$4,$5)`,
		a, contextA, sourceA, entityA, planA); err != nil {
		t.Fatalf("silo own provenance: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM `+schemaA+`.nms_import_plans
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a, contextA, planA); err == nil {
		t.Fatal("silo provenance was erased by deleting its plan")
	}
	// A silo provisioned before the target-revision migration receives both
	// the new column and its CHECK on catch-up, not only the public schema.
	if _, err := pool.Exec(ctx, `ALTER TABLE `+schemaA+`.nms_import_rows
		DROP CONSTRAINT IF EXISTS nms_import_rows_target_fingerprint_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE `+schemaA+`.nms_import_rows
		DROP COLUMN target_fingerprint`); err != nil {
		t.Fatal(err)
	}
	if err := prov.CatchUpSchema(ctx, a); err != nil {
		t.Fatalf("catch up import target revision in existing silo: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schemaA+`.nms_import_rows
		SET target_fingerprint=NULL WHERE tenant_id=$1 AND context_id=$2
		  AND plan_id=$3 AND row_number=0`, a, contextA, planA); err == nil {
		t.Fatal("caught-up silo accepted an update without a target fingerprint")
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schemaA+`.nms_import_rows
		SET target_fingerprint=$4 WHERE tenant_id=$1 AND context_id=$2
		  AND plan_id=$3 AND row_number=0`, a, contextA, planA,
		strings.Repeat("d", 64)); err != nil {
		t.Fatalf("caught-up silo rejected a valid target fingerprint: %v", err)
	}
}
