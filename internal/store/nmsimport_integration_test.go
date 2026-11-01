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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/nmsimport"
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
	// The capture service must use the same RLS and compound-FK boundary as
	// direct storage writes. Its source page has no authority to set context.
	capturer := nmsimport.NewCaptureStore(pool)
	captureA := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	capturePlan, err := capturer.StartPlan(captureA, contextA, nmsimport.LibreNMS,
		"lab", strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("start tenant-scoped capture plan: %v", err)
	}
	if _, err := capturer.StartPlan(captureA, uuid.NewString(), nmsimport.LibreNMS,
		"lab", strings.Repeat("b", 64)); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("unknown routing context started a plan: %v", err)
	}
	page := `{"status":"ok","devices":[{"device_id":17,"display":"Edge R1","ip":"10.42.0.1","community":"source-only-secret"}]}`
	appendPage := func(scope context.Context, routingContext, plan string, pageNo, firstRow int64, payload string) (string, error) {
		return capturer.AppendPage(scope, routingContext, plan, pageNo, "devices", firstRow, strings.NewReader(payload))
	}
	pageHash, err := appendPage(captureA, contextA, capturePlan, 0, 0, page)
	if err != nil || len(pageHash) != 64 {
		t.Fatalf("capture own page: hash=%q err=%v", pageHash, err)
	}
	if retry, err := appendPage(captureA, contextA, capturePlan, 0, 0, page); err != nil || retry != pageHash {
		t.Fatalf("exact retry changed capture: hash=%q err=%v", retry, err)
	}
	secondPage := strings.Replace(strings.Replace(page, `"device_id":17`, `"device_id":18`, 1),
		"Edge R1", "Edge R2", 1)
	if _, err := appendPage(captureA, contextA, capturePlan, 1, 1, secondPage); err != nil {
		t.Fatalf("next contiguous capture page: %v", err)
	}
	if retry, err := appendPage(captureA, contextA, capturePlan, 0, 0, page); err != nil || retry != pageHash {
		t.Fatalf("earlier page retry changed capture: hash=%q err=%v", retry, err)
	}
	changed := strings.Replace(page, "Edge R1", "Changed R1", 1)
	for name, candidate := range map[string]struct {
		scope, routingContext, plan, payload string
		pageNo, firstRow                     int64
		errWant                              error
	}{
		"foreign tenant":      {b.ID, contextA, capturePlan, page, 0, 0, nmsimport.ErrPlanUnavailable},
		"foreign context":     {a.ID, contextOther, capturePlan, page, 0, 0, nmsimport.ErrPlanUnavailable},
		"changed retry":       {a.ID, contextA, capturePlan, changed, 0, 0, nmsimport.ErrInvalidPage},
		"skipped page":        {a.ID, contextA, capturePlan, page, 3, 2, nmsimport.ErrInvalidPage},
		"duplicate source ID": {a.ID, contextA, capturePlan, page, 2, 2, nmsimport.ErrInvalidPage},
	} {
		_, err := appendPage(tenancy.WithTenant(ctx, tenancy.ID(candidate.scope)), candidate.routingContext,
			candidate.plan, candidate.pageNo, candidate.firstRow, candidate.payload)
		if !errors.Is(err, candidate.errWant) {
			t.Fatalf("%s: got %v, want %v", name, err, candidate.errWant)
		}
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var pageCount, rowCount int
		var label, action string
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages WHERE plan_id=$1`, capturePlan).
			Scan(&pageCount); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),max(label),max(action)
			FROM nms_import_rows WHERE plan_id=$1`, capturePlan).
			Scan(&rowCount, &label, &action); err != nil {
			return err
		}
		if pageCount != 2 || rowCount != 2 || label != "Edge R2" || action != "captured" {
			t.Fatalf("capture/retry wrote unexpected rows: pages=%d rows=%d label=%q action=%q",
				pageCount, rowCount, label, action)
		}
		var rawLeak bool
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%source-only-secret%')`,
			capturePlan).Scan(&rawLeak); err != nil {
			return err
		}
		if rawLeak {
			t.Fatal("source credential escaped into normalized capture")
		}
		return nil
	})
	sealedHash, err := capturer.Seal(captureA, contextA, capturePlan, 2, 2)
	if err != nil || len(sealedHash) != 64 {
		t.Fatalf("seal complete capture: hash=%q err=%v", sealedHash, err)
	}
	if retry, err := capturer.Seal(captureA, contextA, capturePlan, 2, 2); err != nil || retry != sealedHash {
		t.Fatalf("exact seal retry changed hash: %q %v", retry, err)
	}
	if _, err := appendPage(captureA, contextA, capturePlan, 2, 2, page); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("sealed plan accepted another page: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state, storedHash string
		var storedRows int64
		if err := sc.Q.QueryRow(ctx, `SELECT state,snapshot_hash,row_count FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextA, capturePlan).
			Scan(&state, &storedHash, &storedRows); err != nil {
			return err
		}
		if state != "sealed" || storedHash != sealedHash || storedRows != 2 {
			t.Fatalf("sealed plan published wrong metadata: state=%q hash=%q rows=%d", state, storedHash, storedRows)
		}
		return nil
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE nms_import_pages SET page_hash=$4
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND page_number=1`,
			a.ID, contextA, capturePlan, strings.Repeat("c", 64))
		return err
	})
	if _, err := capturer.Seal(captureA, contextA, capturePlan, 2, 2); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("tampered page receipt retained a valid sealed plan: %v", err)
	}
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
		 address,target_entity_id)
		VALUES ($1,$2,$3,0,'device','17','10.42.0.1',$4)`,
		a.ID, contextA, planA, entityA); err != nil {
		t.Fatalf("own plan row: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var action string
		if err := sc.Q.QueryRow(ctx, `SELECT action FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND row_number=0`,
			a.ID, contextA, planA).Scan(&action); err != nil {
			return err
		}
		if action != "captured" {
			t.Fatalf("unreviewed source row became an apply action: %s", action)
		}
		return nil
	})
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
	// A target removed during ordinary tenant operation invalidates its old
	// import row and provenance. It must not require a SET NULL write when
	// full-tenant deletion later cascades through the same FK.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `DELETE FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextA, entityA); err != nil {
			return err
		}
		var rows, provenance, plans int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, a.ID, contextA, planA).
			Scan(&rows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_provenance
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, a.ID, contextA, planA).
			Scan(&provenance); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextA, planA).
			Scan(&plans); err != nil {
			return err
		}
		if rows != 0 || provenance != 0 || plans != 1 {
			t.Fatalf("target deletion left stale import binding: rows=%d provenance=%d plans=%d",
				rows, provenance, plans)
		}
		return nil
	})
}
