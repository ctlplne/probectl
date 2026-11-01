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
	"io"
	"math"
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
	// Capture progress is stored on the FORCE-RLS plan row. A direct scoped
	// update cannot advance or observe another tenant's matching context/plan.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		updated, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_stage='locations',capture_start_page=2,capture_start_row=10001,
			capture_lease_hash=$3,capture_lease_until=clock_timestamp()+interval '30 seconds'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$4`,
			a.ID, contextA, strings.Repeat("c", 64), planA)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return fmt.Errorf("own capture cursor update: rows=%d", updated.RowsAffected())
		}
		foreign, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET capture_stage='complete'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, b.ID, contextA, planB)
		if err != nil {
			return err
		}
		if foreign.RowsAffected() != 0 {
			return fmt.Errorf("foreign capture cursor update: rows=%d", foreign.RowsAffected())
		}
		var visible int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, b.ID, contextA, planB).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			return fmt.Errorf("foreign capture cursor visible under tenant RLS")
		}
		return nil
	})
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var stage string
		if err := sc.Q.QueryRow(ctx, `SELECT capture_stage FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, b.ID, contextA, planB).Scan(&stage); err != nil {
			return err
		}
		if stage != "devices" {
			return fmt.Errorf("foreign cursor changed to %q", stage)
		}
		return nil
	})
	// The capture service must use the same RLS and compound-FK boundary as
	// direct storage writes. Its source page has no authority to set context.
	auditErr := errors.New("tenant audit append failed")
	auditActions := map[string]int{}
	var failAuditAction string
	capturer := nmsimport.NewCaptureStore(pool, func(_ context.Context, _ tenancy.Scope,
		action, target string, details map[string]any) error {
		if target == "" || details["context_id"] != contextA {
			return errors.New("capture audit lost its plan or routing context")
		}
		if action == failAuditAction {
			return auditErr
		}
		auditActions[action]++
		return nil
	})
	captureA := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	failAuditAction = "nms_import.capture_started"
	if _, err := capturer.StartPlan(captureA, contextA, nmsimport.LibreNMS,
		"audit-reject", strings.Repeat("b", 64)); !errors.Is(err, auditErr) {
		t.Fatalf("plan creation did not roll back with its tenant audit: %v", err)
	}
	failAuditAction = ""
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_sources
			WHERE tenant_id=$1 AND context_id=$2 AND instance_ref='audit-reject'`,
			a.ID, contextA).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("failed audit left a source configuration behind")
		}
		return nil
	})
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
	thirdPage := strings.Replace(strings.Replace(page, `"device_id":17`, `"device_id":19`, 1),
		"Edge R1", "Edge R3", 1)
	failAuditAction = "nms_import.page_captured"
	if _, err := appendPage(captureA, contextA, capturePlan, 2, 2, thirdPage); !errors.Is(err, auditErr) {
		t.Fatalf("page capture did not roll back with its tenant audit: %v", err)
	}
	failAuditAction = ""
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
	if _, err := capturer.Seal(captureA, contextA, capturePlan, math.MaxInt64, 2); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("fabricated page total was accepted: %v", err)
	}
	failAuditAction = "nms_import.capture_sealed"
	if _, err := capturer.Seal(captureA, contextA, capturePlan, 2, 2); !errors.Is(err, auditErr) {
		t.Fatalf("seal did not fail with its tenant audit: %v", err)
	}
	failAuditAction = ""
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextA, capturePlan).
			Scan(&state); err != nil {
			return err
		}
		if state != "capturing" {
			t.Fatalf("failed audit published a sealed plan: %q", state)
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
	if auditActions["nms_import.capture_started"] != 1 ||
		auditActions["nms_import.page_captured"] != 2 ||
		auditActions["nms_import.capture_sealed"] != 1 {
		t.Fatalf("capture audit actions duplicated or omitted: %+v", auditActions)
	}
	// A complete source plan can bind device and location pages without
	// letting the location label pick a destination routing context.
	locationsPlan, err := capturer.StartPlan(captureA, contextA, nmsimport.LibreNMS,
		"lab-locations", strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendPage(captureA, contextA, locationsPlan, 0, 0, page); err != nil {
		t.Fatalf("capture mixed-plan device page: %v", err)
	}
	locations := `{"status":"ok","locations":[{"id":5,"location":"West DC","notes":"secret-note-123"}],"count":1}`
	if _, err := capturer.AppendPage(captureA, contextA, locationsPlan, 1,
		"locations", 1, strings.NewReader(locations)); err != nil {
		t.Fatalf("capture mixed-plan location page: %v", err)
	}
	if _, err := capturer.Seal(captureA, contextA, locationsPlan, 2, 2); err != nil {
		t.Fatalf("seal device and location source snapshot: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var kind, label string
		var leaked bool
		if err := sc.Q.QueryRow(ctx, `SELECT object_kind,label FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3 AND row_number=1`,
			a.ID, contextA, locationsPlan).Scan(&kind, &label); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%secret-note-123%')`,
			locationsPlan).Scan(&leaked); err != nil {
			return err
		}
		if kind != "site" || label != "West DC" || leaked {
			t.Fatalf("location row lost site identity or retained source metadata: kind=%q label=%q leaked=%v", kind, label, leaked)
		}
		return nil
	})
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
	if err := tryA(`INSERT INTO nms_import_capture_steps
		(tenant_id,context_id,plan_id,resource_kind,start_page,end_page,start_row,end_row)
		VALUES ($1,$2,$3,'devices',0,1,0,0)`, a.ID, contextA, planA); err != nil {
		t.Fatalf("own capture step rejected: %v", err)
	}
	if err := tryA(`INSERT INTO nms_import_capture_steps
		(tenant_id,context_id,plan_id,resource_kind,start_page,end_page,start_row,end_row)
		VALUES ($1,$2,$3,'devices',0,1,0,0)`, b.ID, contextA, planB); err == nil {
		t.Fatal("tenant A wrote tenant B's capture step")
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var visible int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, b.ID, contextA, planB).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			return fmt.Errorf("foreign capture step visible under tenant RLS")
		}
		return nil
	})
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

func TestNMSImportLibreNMSStreamSealsOnlyCompleteTenantCapture(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "import-stream-a-"+suffix, "Stream A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "import-stream-b-"+suffix, "Stream B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove import stream tenants: %v", err)
		}
	})
	routingContext := uuid.NewString()
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,'stream site','stream vrf')`,
			a.ID, routingContext, uuid.NewString(), uuid.NewString())
		return err
	})
	auditEvents := 0
	capturer := nmsimport.NewCaptureStore(pool, func(_ context.Context, sc tenancy.Scope,
		_, _ string, _ map[string]any) error {
		if sc.Tenant.String() != a.ID {
			return errors.New("stream capture crossed the tenant audit boundary")
		}
		auditEvents++
		return nil
	})
	scopeA := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	start := func(instance string) string {
		t.Helper()
		id, err := capturer.StartPlan(scopeA, routingContext, nmsimport.LibreNMS,
			instance, strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	completePlan := start("stream-complete")
	complete := `{"status":"ok","devices":[
		{"device_id":17,"display":"Edge A","ip":"10.42.0.1","location_id":5,"community":"source-only-secret"},
		{"device_id":18,"display":"Edge B","ip":"10.42.0.2","location_id":5}],"count":2}`
	foreignInput := &observedImportReader{Reader: strings.NewReader(complete)}
	if _, err := capturer.CaptureLibreNMSDevices(tenancy.WithTenant(ctx, tenancy.ID(b.ID)),
		routingContext, completePlan, foreignInput); !errors.Is(err, nmsimport.ErrPlanUnavailable) || foreignInput.reads != 0 {
		t.Fatalf("foreign tenant consumed source before plan lookup: reads=%d err=%v", foreignInput.reads, err)
	}
	sealedHash, err := capturer.CaptureLibreNMSDevices(scopeA, routingContext,
		completePlan, strings.NewReader(complete))
	if err != nil || len(sealedHash) != 64 {
		t.Fatalf("complete source stream did not seal: hash=%q err=%v", sealedHash, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		var pages, rows int
		var leaked bool
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, completePlan).Scan(&state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages WHERE plan_id=$1`, completePlan).Scan(&pages); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows WHERE plan_id=$1`, completePlan).Scan(&rows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%source-only-secret%')`,
			completePlan).Scan(&leaked); err != nil {
			return err
		}
		if state != "sealed" || pages != 1 || rows != 2 || leaked {
			return fmt.Errorf("bad stream capture: state=%s pages=%d rows=%d leaked=%v", state, pages, rows, leaked)
		}
		return nil
	})
	partialPlan := start("stream-partial")
	if _, err := capturer.CaptureLibreNMSDevices(scopeA, routingContext, partialPlan,
		strings.NewReader(`{"devices":[{"device_id":19,"display":"Edge C","ip":"10.42.0.3","location_id":5}],"status":"error"}`)); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("invalid final response published a capture: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, partialPlan).Scan(&state); err != nil {
			return err
		}
		if state != "capturing" {
			return fmt.Errorf("invalid source stream became actionable: %s", state)
		}
		return nil
	})
	if _, err := capturer.CaptureLibreNMSDevices(scopeA, routingContext, partialPlan,
		strings.NewReader(`{"devices":[{"device_id":19,"display":"Edge C","ip":"10.42.0.3","location_id":5}],"status":"ok","count":1}`)); err != nil {
		t.Fatalf("exact capture retry did not finish the inert plan: %v", err)
	}
	emptyPlan := start("stream-empty")
	if _, err := capturer.CaptureLibreNMSDevices(scopeA, routingContext, emptyPlan,
		strings.NewReader(`{"status":"ok","devices":[],"count":0}`)); err != nil {
		t.Fatalf("complete empty source refused: %v", err)
	}
	if auditEvents != 9 { // three starts; complete, partial and empty pages; three seals, no duplicate retry page
		t.Fatalf("missing or duplicated tenant audit events: %d", auditEvents)
	}
	mixedPlan := start("stream-devices-locations")
	mixedSites := `{"locations":[{"id":5,"location":"West DC","notes":"source-only-site-secret"}],"status":"ok","count":1}`
	if hash, err := capturer.CaptureLibreNMSDevicesAndLocations(scopeA, routingContext,
		mixedPlan, strings.NewReader(complete), strings.NewReader(mixedSites)); err != nil || len(hash) != 64 {
		t.Fatalf("complete device/location stream did not seal: hash=%q err=%v", hash, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state, kind, label string
		var pages, rows int
		var leaked bool
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, mixedPlan).Scan(&state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages WHERE plan_id=$1`, mixedPlan).Scan(&pages); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows WHERE plan_id=$1`, mixedPlan).Scan(&rows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT object_kind,label FROM nms_import_rows
			WHERE plan_id=$1 AND external_id='5'`, mixedPlan).Scan(&kind, &label); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%source-only-site-secret%')`,
			mixedPlan).Scan(&leaked); err != nil {
			return err
		}
		if state != "sealed" || pages != 2 || rows != 3 || kind != "site" || label != "West DC" || leaked {
			return fmt.Errorf("mixed stream capture: state=%s pages=%d rows=%d kind=%s label=%s leaked=%v",
				state, pages, rows, kind, label, leaked)
		}
		return nil
	})
	if auditEvents != 13 { // mixed start, device page, location page and seal each append once
		t.Fatalf("mixed stream duplicated or omitted tenant audit events: %d", auditEvents)
	}
	incompleteMixed := start("stream-missing-locations")
	if _, err := capturer.CaptureLibreNMSDevicesAndLocations(scopeA, routingContext,
		incompleteMixed, strings.NewReader(complete),
		strings.NewReader(`{"status":"error","locations":[]}`)); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("invalid location response published a mixed plan: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		var pages int
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`,
			incompleteMixed).Scan(&state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages WHERE plan_id=$1`,
			incompleteMixed).Scan(&pages); err != nil {
			return err
		}
		if state != "capturing" || pages != 1 {
			return fmt.Errorf("incomplete mixed stream became actionable: state=%s pages=%d", state, pages)
		}
		return nil
	})
	fullPlan := start("stream-full-inventory")
	groups := `[{"status":"ok","groups":[{"id":7,"name":"WAN","pattern":"source-only-predicate"}],"count":1}]`
	rules := `{"status":"ok","rules":[{"id":9,"name":"Link down","rule":"source-only-expression"}],"count":1}`
	members := `[{"status":"ok","devices":[{"device_id":17,"community":"source-only-membership-secret"}],"count":1}]`
	memberLists := []nmsimport.LibreNMSMembershipList{{GroupID: "7", GroupName: "WAN", Raw: strings.NewReader(members)}}
	if _, err := capturer.CaptureLibreNMSInventory(scopeA, routingContext, fullPlan,
		strings.NewReader(complete), strings.NewReader(mixedSites), strings.NewReader(groups),
		strings.NewReader(rules), memberLists); err != nil {
		t.Fatalf("complete five-resource inventory did not seal: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state, kind, unmapped string
		var pages, rows int
		var leaked bool
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, fullPlan).Scan(&state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_pages WHERE plan_id=$1`, fullPlan).Scan(&pages); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows WHERE plan_id=$1`, fullPlan).Scan(&rows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT object_kind,unmapped_codes[1] FROM nms_import_rows
			WHERE plan_id=$1 AND external_id='7:17'`, fullPlan).Scan(&kind, &unmapped); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%source-only-%')`, fullPlan).Scan(&leaked); err != nil {
			return err
		}
		if state != "sealed" || pages != 5 || rows != 6 || kind != "membership" ||
			unmapped != "group_unmapped" || leaked {
			return fmt.Errorf("full inventory lost a review-only membership or leaked source data: state=%s pages=%d rows=%d kind=%s unmapped=%s leaked=%v",
				state, pages, rows, kind, unmapped, leaked)
		}
		return nil
	})
	missingMemberPlan := start("stream-missing-member-list")
	if _, err := capturer.CaptureLibreNMSInventory(scopeA, routingContext, missingMemberPlan,
		strings.NewReader(complete), strings.NewReader(mixedSites), strings.NewReader(groups),
		strings.NewReader(rules), nil); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("missing membership list sealed a partial inventory: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, missingMemberPlan).Scan(&state); err != nil {
			return err
		}
		if state != "capturing" {
			return fmt.Errorf("missing membership list published plan: %s", state)
		}
		return nil
	})
	foreignGroupPlan := start("stream-foreign-group")
	foreignGroupBody := &observedImportReader{Reader: strings.NewReader(members)}
	if _, err := capturer.CaptureLibreNMSInventory(scopeA, routingContext, foreignGroupPlan,
		strings.NewReader(complete), strings.NewReader(mixedSites), strings.NewReader(groups),
		strings.NewReader(rules), []nmsimport.LibreNMSMembershipList{{GroupID: "8", GroupName: "WAN", Raw: foreignGroupBody}}); !errors.Is(err, nmsimport.ErrInvalidPage) || foreignGroupBody.reads != 0 {
		t.Fatalf("foreign group consumed a membership response: reads=%d err=%v", foreignGroupBody.reads, err)
	}
	renamedGroupPlan := start("stream-renamed-group")
	renamedGroupBody := &observedImportReader{Reader: strings.NewReader(members)}
	if _, err := capturer.CaptureLibreNMSInventory(scopeA, routingContext, renamedGroupPlan,
		strings.NewReader(complete), strings.NewReader(mixedSites), strings.NewReader(groups),
		strings.NewReader(rules), []nmsimport.LibreNMSMembershipList{{GroupID: "7", GroupName: "renamed", Raw: renamedGroupBody}}); !errors.Is(err, nmsimport.ErrInvalidPage) || renamedGroupBody.reads != 0 {
		t.Fatalf("changed group name consumed a membership response: reads=%d err=%v", renamedGroupBody.reads, err)
	}
}

type observedImportReader struct {
	io.Reader
	reads int
}

func (r *observedImportReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}
