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
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Uses the application role and real FORCE RLS. The counterexample removes
// only the format policy, keeping the tenant policy and all original rows.
func TestReportArtifactChunksTenantIsolationAndLegacyRefusal(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	tenants := make([]string, 2)
	for i := range tenants {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("artifact-chunks-%d-%d", i, time.Now().UnixNano()), "Report chunks")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != code {
			t.Fatalf("SQL refusal=%v, want SQLSTATE %s", err, code)
		}
	}
	for i, tenant := range tenants {
		err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (DashboardReports{}).CreateView(ctx, sc, DashboardViewInput{ID: "same-view", OwnerID: "alice", Name: "Owned report", Preset: "operator", Definition: []byte(`{}`)}); err != nil {
				return err
			}
			ids := []string{"same-artifact"}
			if i == 1 {
				ids = append(ids, "foreign-only")
			}
			for _, id := range ids {
				_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
      (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,
       absolute_from,absolute_to,provenance,redaction_state,coverage_limitations,
       body_storage,body_bytes,body_digest,source_capture)
      VALUES($1,$2,'same-view','csv','text/csv','owned.csv',NULL,'alice',
       statement_timestamp()-interval '1 hour',statement_timestamp(),'[]','none','[]',
       'chunks',4,decode(repeat('00',32),'hex'),jsonb_build_object('version',1,'tenant_id',$1::text))`, tenant, id)
				if err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,$2,0,$3)`, tenant, id, []byte("body")); err != nil {
					return err
				}
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
      (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,
       absolute_from,absolute_to,provenance,redaction_state,coverage_limitations)
      VALUES($1,'legacy','same-view','csv','text/csv','legacy.csv',$2,'alice',
       statement_timestamp()-interval '1 hour',statement_timestamp(),'[]','none','[]')`, tenant, []byte("legacy exact bytes"))
			return err
		})
		if err != nil {
			t.Fatal("owned parent/chunk positive failed", err)
		}
	}
	for _, tenant := range tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT content FROM dashboard_report_artifact_chunks WHERE artifact_id='same-artifact'`).Scan(&body); err != nil {
				return err
			}
			if string(body) != "body" {
				t.Fatal("owned chunk bytes changed")
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks WHERE tenant_id<>$1`, tenant).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("foreign chunk escaped storage RLS")
			}
			if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.report_artifact_format','',true)`); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT content FROM dashboard_report_artifacts WHERE id='legacy'`).Scan(&body); err != nil {
				return err
			}
			if string(body) != "legacy exact bytes" {
				t.Fatal("legacy inline bytes changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	expectCode(run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'foreign-only',0,$2)`, tenants[0], []byte("no"))
		return err
	}), "23503")
	expectCode(run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',1,$2)`, tenants[1], []byte("no"))
		return err
	}), "42501")
	for _, table := range []string{"dashboard_report_artifacts", "dashboard_report_artifact_chunks"} {
		expectCode(run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE `+table+` SET content=$1`, []byte("no"))
			return err
		}), "42501")
	}
	// A raw old application transaction has no capability marker. Missing
	// tenant yields zero rows; provider gets no implicit report byte access.
	for _, role := range []string{"probectl_app", "probectl_provider"} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		var count int
		err = tx.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks`).Scan(&count)
		_ = tx.Rollback(ctx)
		if err == nil && count != 0 {
			t.Fatal("unbound/provider transaction read report chunks")
		}
		if err != nil {
			expectCode(err, "42501")
		}
	}
	t.Run("success", func(t *testing.T) {
		if os.Getenv("PROBECTL_QA_REPORT_FORMAT_OMIT") == "1" {
			if _, err := pool.Exec(ctx, `ALTER POLICY report_artifact_format ON dashboard_report_artifacts USING(true) WITH CHECK(true)`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, err := pool.Exec(context.Background(), `ALTER POLICY report_artifact_format ON dashboard_report_artifacts USING (`+tenancy.ReportArtifactFormatPredicate+`) WITH CHECK (`+tenancy.ReportArtifactFormatPredicate+`)`)
				if err != nil {
					t.Error(err)
				}
			})
		}
		err := run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.report_artifact_format','',true)`); err != nil {
				return err
			}
			var body []byte
			return sc.Q.QueryRow(ctx, `SELECT content FROM dashboard_report_artifacts WHERE id='same-artifact'`).Scan(&body)
		})
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "0A000" {
			t.Fatalf("legacy reader did not refuse chunk representation: %v", err)
		}
	})
	if err := run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM dashboard_report_artifacts WHERE id='same-artifact'`)
		if err != nil {
			return err
		}
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("parent cascade left owned chunks")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := run(tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks`).Scan(&count); err != nil {
			return err
		}
		if count != 2 {
			t.Fatal("tenant A cascade changed tenant B chunks")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
