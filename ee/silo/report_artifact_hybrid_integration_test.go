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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Hybrid routes control state to public while telemetry targets stay isolated.
// Do not corrupt public schema or invent a tenant schema to simulate catch-up.
func proveHybridReportChunks(t *testing.T, pool *pgxpool.Pool, prov *Provisioner) {
	t.Helper()
	ctx := t.Context()
	ids := []string{mkTenant(t, pool, fmt.Sprintf("report-hybrid-a-%d", time.Now().UnixNano()), "hybrid", ""), mkTenant(t, pool, fmt.Sprintf("report-hybrid-b-%d", time.Now().UnixNano()), "hybrid", "")}
	previous := tenancy.CurrentRouter()
	router := NewRouter(pool, nil, time.Minute)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(previous) })
	t.Cleanup(func() {
		for _, id := range ids {
			if err := prov.Teardown(context.Background(), id, "", tenancy.IsolationHybrid); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids); err != nil {
			t.Error(err)
		}
	})
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	for i, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationHybrid); err != nil {
			t.Fatal(err)
		}
		targets, err := router.TargetsFor(ctx, id)
		if err != nil || targets.Model != tenancy.IsolationHybrid || targets.PGSchema != "" || targets.CHDatabase != CHDatabase(id) {
			t.Fatal("hybrid report state did not retain the existing pooled routing contract", err, targets)
		}
		var schemaExists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, SchemaName(id)).Scan(&schemaExists); err != nil || schemaExists {
			t.Fatal("hybrid unexpectedly provisioned a Postgres tenant schema", err)
		}
		if err := run(id, func(ctx context.Context, sc tenancy.Scope) error {
			var schema string
			var table, parent bool
			if err := sc.Q.QueryRow(ctx, `SELECT current_schema(),
 to_regclass('dashboard_report_artifact_chunks')='public.dashboard_report_artifact_chunks'::regclass,
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.dashboard_report_artifact_chunks'::regclass
 AND conname='dashboard_report_artifact_chunks_artifact_fk' AND confrelid='public.dashboard_report_artifacts'::regclass)`).Scan(&schema, &table, &parent); err != nil {
				return err
			}
			if schema != "public" || !table || !parent {
				t.Fatal("hybrid app transaction did not resolve the actual public report tables and parent")
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_views(tenant_id,id,owner_id,name,preset,definition) VALUES($1,'same-view','alice','Hybrid report','operator','{}')`, id); err != nil {
				return err
			}
			artifacts := []string{"same-artifact"}
			if i == 1 {
				artifacts = append(artifacts, "foreign-only")
			}
			body := []byte("hybrid-" + id)
			for _, artifact := range artifacts {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
 (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
 VALUES($1,$2,'same-view','csv','text/csv','hybrid.csv',NULL,'alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none','chunks',$3,decode(repeat('00',32),'hex'),jsonb_build_object('version',$4::int,'tenant_id',$1::uuid::text))`, id, artifact, len(body), i+1); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,$2,0,$3)`, id, artifact, body); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal("hybrid owned report publication fixture", err)
		}
	}
	for i, id := range ids {
		if err := run(id, func(ctx context.Context, sc tenancy.Scope) error {
			var owner string
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT tenant_id::text,content FROM dashboard_report_artifact_chunks WHERE artifact_id='same-artifact'`).Scan(&owner, &body); err != nil {
				return err
			}
			if owner != id || string(body) != "hybrid-"+id {
				t.Fatal("hybrid same-ID report read another tenant's bytes")
			}
			var count, foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks`).Scan(&count); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks WHERE tenant_id=$1`, ids[1-i]).Scan(&foreign); err != nil {
				return err
			}
			if count != i+1 || foreign != 0 {
				t.Fatal("hybrid pooled storage RLS exposed foreign report rows", count, foreign)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != code {
			t.Fatalf("hybrid refusal=%v, want SQLSTATE%s", err, code)
		}
	}
	expectCode(run(ids[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'foreign-only',1,'no')`, ids[0])
		return err
	}), "23503")
	expectCode(run(ids[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,'same-artifact',2,'no')`, ids[1])
		return err
	}), "42501")
	for _, sql := range []string{`UPDATE dashboard_report_artifact_chunks SET content='changed'`, `UPDATE dashboard_report_artifacts SET content='changed'`} {
		expectCode(run(ids[0], func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, sql)
			return err
		}), "42501")
	}
	expectCode(run(ids[0], func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.report_artifact_format','',true)`); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `SELECT content FROM dashboard_report_artifacts WHERE id='same-artifact'`)
		return err
	}), "0A000")
	if err := tenancy.InTenant(ctx, pool, func(context.Context, tenancy.Scope) error { return nil }); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("hybrid report storage accepted a missing tenant", err)
	}
}
