// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestReportArtifactChunksSiloCatchUpKeepsLocalParentsAndImmutableBodies(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, model := range []tenancy.IsolationModel{tenancy.IsolationSiloed, tenancy.IsolationHybrid} {
		t.Run(string(model), func(t *testing.T) {
			if model == tenancy.IsolationHybrid {
				proveHybridReportChunks(t, pool, prov)
				return
			}
			ids := []string{mkTenant(t, pool, fmt.Sprintf("report-%s-a-%d", model, time.Now().UnixNano()), string(model), ""), mkTenant(t, pool, fmt.Sprintf("report-%s-b-%d", model, time.Now().UnixNano()), string(model), "")}
			t.Cleanup(func() {
				for _, id := range ids {
					if err := prov.Teardown(context.Background(), id, "", model); err != nil {
						t.Error(err)
					}
				}
				if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids); err != nil {
					t.Error(err)
				}
			})
			for lane, id := range ids {
				if err := prov.Provision(ctx, id, "", model); err != nil {
					t.Fatal(err)
				}
				schema := quoteIdent(SchemaName(id))
				// Simulate an old empty report table and restored overly broad grant.
				// Catch-up must repair every control, and be idempotent.
				for _, sql := range []string{
					`ALTER TABLE ` + schema + `.dashboard_report_artifacts ALTER COLUMN content SET NOT NULL`,
					`ALTER TABLE ` + schema + `.dashboard_report_artifacts DROP CONSTRAINT dashboard_report_artifacts_body_representation_v6`,
					`ALTER TABLE ` + schema + `.dashboard_report_artifacts ADD CONSTRAINT dashboard_report_artifacts_body_representation_v2 CHECK(body_storage='inline') NOT VALID`,
					`DROP POLICY report_artifact_format ON ` + schema + `.dashboard_report_artifacts`,
					`ALTER TABLE ` + schema + `.dashboard_report_artifact_chunks DROP CONSTRAINT dashboard_report_artifact_chunks_artifact_fk`,
					`DROP TRIGGER tenant_write_fence ON ` + schema + `.dashboard_report_artifact_chunks`,
					`ALTER TABLE ` + schema + `.dashboard_report_schedules DROP CONSTRAINT IF EXISTS report_schedule_dashboard_fk`,
					`ALTER TABLE ` + schema + `.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS report_artifact_dashboard_fk`,
					`ALTER TABLE ` + schema + `.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS report_artifact_schedule_fk`,
					`GRANT UPDATE ON ` + schema + `.dashboard_report_artifacts,` + schema + `.dashboard_report_artifact_chunks TO probectl_app`,
				} {
					if _, err := pool.Exec(ctx, sql); err != nil {
						t.Fatal(err)
					}
				}
				for range 2 {
					if err := prov.CatchUp(ctx, id); err != nil {
						t.Fatal("report storage catch-up", err)
					}
				}
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_views(tenant_id,id,owner_id,name,preset,definition) VALUES($1,'same-view','alice','Owned view','operator','{}')`, id); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifacts
      (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
      VALUES($1,'same-artifact','same-view','csv','text/csv','owned.csv',NULL,'alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none','chunks',4,decode(repeat('00',32),'hex'),jsonb_build_object('version',$2::int,'tenant_id',$1::uuid::text))`, id, lane+1); err != nil {
					t.Fatal("silo rejected own chunk parent", err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',0,$2)`, id, []byte("body")); err != nil {
					t.Fatal("silo rejected own chunk", err)
				}
				// Preserve the original version1/2 parents above and add a
				// separate complete version3 parent in EACH physical silo.
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifacts
 (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
 VALUES($1,'same-monthly','same-view','csv','text/csv','monthly.csv',NULL,'alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none','chunks',4,decode(repeat('00',32),'hex'),jsonb_build_object('version',3,'tenant_id',$1::uuid::text))`, id); err != nil {
					t.Fatal("silo rejected monthly version3 parent", err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-monthly',0,'body')`, id); err != nil {
					t.Fatal(err)
				}
				var stateUpdate, bodyUpdate bool
				if err := pool.QueryRow(ctx, `SELECT has_column_privilege('probectl_app',$1,'email_state','UPDATE'),has_column_privilege('probectl_app',$1,'content','UPDATE')`, schema+`.dashboard_report_artifacts`).Scan(&stateUpdate, &bodyUpdate); err != nil || !stateUpdate || bodyUpdate {
					t.Fatal("silo retry-state rights changed body immutability", err)
				}

				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifacts
      (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
      VALUES($1,'same-static','same-view','csv','text/csv','static.csv',NULL,'alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none','document-chunks',4,decode(repeat('00',32),'hex'),NULL)`, id); err != nil {
					t.Fatal("silo rejected explicit static chunk format", err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-static',0,$2)`, id, []byte("data")); err != nil {
					t.Fatal(err)
				}
				var fkTarget string
				if err := pool.QueryRow(ctx, `SELECT confrelid::regclass::text FROM pg_constraint WHERE conrelid=$1::regclass AND conname='dashboard_report_artifact_chunks_artifact_fk'`, schema+`.dashboard_report_artifact_chunks`).Scan(&fkTarget); err != nil {
					t.Fatal(err)
				}
				if fkTarget != SchemaName(id)+`.dashboard_report_artifacts` {
					t.Fatalf("chunk FK falls through to another schema: %s", fkTarget)
				}
			}
			read := func(tenant, _, sql string, capable bool) error {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
					return err
				}
				capability := ""
				if capable {
					capability = "1"
				}
				if _, err = tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true),set_config('probectl.report_artifact_format',$2,true)`, tenant, capability); err != nil {
					return err
				}
				_, err = tx.Exec(ctx, sql)
				return err
			}
			own := quoteIdent(SchemaName(ids[0]))
			other := quoteIdent(SchemaName(ids[1]))
			if err := read(ids[0], own, `SELECT content FROM `+own+`.dashboard_report_artifact_chunks`, true); err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`)
			if err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true),set_config('probectl.report_artifact_format','1',true)`, ids[0])
			if err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var count int
			err = tx.QueryRow(ctx, `SELECT count(*) FROM `+other+`.dashboard_report_artifact_chunks`).Scan(&count)
			_ = tx.Rollback(ctx)
			if err != nil || count != 0 {
				t.Fatal("schema-qualified foreign chunks escaped fixed schema RLS", err, count)
			}
			for _, query := range []string{
				`SELECT content FROM ` + own + `.dashboard_report_artifacts`,
				`SELECT content FROM ` + own + `.dashboard_report_artifacts WHERE id='same-static'`,
				`UPDATE ` + own + `.dashboard_report_artifact_chunks SET content='changed'`,
				`UPDATE ` + own + `.dashboard_report_artifacts SET content='changed'`,
			} {
				err := read(ids[0], own, query, false)
				var pgerr *pgconn.PgError
				want := "42501"
				if query[0] == 'S' {
					want = "0A000"
				}
				if !errors.As(err, &pgerr) || pgerr.Code != want {
					t.Fatalf("silo refusal=%v, want %s", err, want)
				}
			}
			// The migration login bypasses RLS: the composite FK alone must reject
			// a parent existing only in the other tenant's physical schema.
			if _, err := pool.Exec(ctx, `INSERT INTO `+own+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',1,$2)`, ids[1], []byte("no")); err == nil {
				t.Fatal("silo child accepted other tenant's parent")
			}
			if _, err := pool.Exec(ctx, `INSERT INTO `+other+`.dashboard_views(tenant_id,id,owner_id,name,preset,definition) VALUES($1,'foreign-view-only','alice','Foreign view','operator','{}')`, ids[1]); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO `+other+`.dashboard_report_schedules(tenant_id,id,dashboard_id,owner_id,name,format,cadence,destination_id,next_run_at) VALUES($1,'foreign-schedule-only','foreign-view-only','alice','Foreign schedule','csv','daily','tenant-report-inbox',statement_timestamp())`, ids[1]); err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{
				`INSERT INTO ` + own + `.dashboard_report_artifacts(tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state) VALUES($1,'bad-dashboard','foreign-view-only','csv','text/csv','bad.csv','legacy','alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none')`,
				`INSERT INTO ` + own + `.dashboard_report_schedules(tenant_id,id,dashboard_id,owner_id,name,format,cadence,destination_id,next_run_at) VALUES($1,'bad-dashboard','foreign-view-only','alice','Bad schedule','csv','daily','tenant-report-inbox',statement_timestamp())`,
				`INSERT INTO ` + own + `.dashboard_report_artifacts(tenant_id,id,dashboard_id,schedule_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state) VALUES($1,'bad-schedule','same-view','foreign-schedule-only','csv','text/csv','bad.csv','legacy','alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none')`,
			} {
				_, err := pool.Exec(ctx, query, ids[0])
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "23503" {
					t.Fatal("silo report parent borrowed a foreign dashboard or schedule", err)
				}
			}
			if _, err := pool.Exec(ctx, `UPDATE public.tenants SET status='offboarding',audit_write_fenced_at=statement_timestamp() WHERE id=$1`, ids[0]); err != nil {
				t.Fatal(err)
			}
			_, err = pool.Exec(ctx, `INSERT INTO `+own+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',1,$2)`, ids[0], []byte("late"))
			var fenced *pgconn.PgError
			if !errors.As(err, &fenced) || fenced.Code != "55000" {
				t.Fatalf("restored silo chunk writer ignored erasure fence: %v", err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO `+other+`.dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',1,$2)`, ids[1], []byte("live")); err != nil {
				t.Fatalf("sibling silo chunk writer blocked: %v", err)
			}
		})
	}
}
