// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This is storage/format proof using complete synthetic bodies, not a rendered
// PDF receipt. The original valid multilingual PDF remains a separate full proof.
func TestStaticDocumentChunksKeepCompleteBodiesAndRejectSourceDowngrade(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	tenants := make([]string, 2)
	bodies := make([][]byte, 2)
	for i := range tenants {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("static-body-%d-%d", i, time.Now().UnixNano()), "Static document")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
		bodies[i] = bytes.Repeat([]byte(fmt.Sprintf("owned-document-lane%d exact-9007199254740993\r\n", i)), 70001)
		if len(bodies[i]) <= 2<<20 {
			t.Fatal("static document storage proof did not cross former ceiling")
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	input := ReportArtifactInput{ID: "same-artifact", DashboardID: "same-view", Format: "csv", MediaType: "text/csv", Filename: "complete.csv", GeneratedBy: "alice", AbsoluteFrom: time.Now().Add(-time.Hour), AbsoluteTo: time.Now(), RedactionState: "none"}
	publish := func(tenant, id, view string, body []byte, rollback bool) error {
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		stage, _, err := reporting.StageBody(bound, tenant, reporting.BodyStageLimitsForBytes(reporting.DefaultCSVLimits().Bytes), func(w io.Writer) error { _, err := w.Write(body); return err })
		if err != nil {
			return err
		}
		defer stage.Close()
		in := input
		in.ID = id
		in.DashboardID = view
		return tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			meta, err := (DashboardReports{}).CreateDocumentChunkedArtifact(ctx, sc, in, stage)
			if err != nil {
				return err
			}
			if meta.BodyStorage != "document-chunks" || len(meta.SourceCapture) != 0 || meta.Content != nil || meta.BodyBytes != int64(len(body)) || len(meta.BodySHA256) != 64 {
				t.Fatal("static body metadata lost explicit source-free format or complete receipt")
			}
			if rollback {
				return errors.New("synthetic publication rollback")
			}
			return nil
		})
	}
	for i, tenant := range tenants {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, view := range []struct{ id, definition string }{{"same-view", `{}`}, {"source-view", `{"flow_sources":[{"id":"00000000-0000-0000-0000-000000000011","version":"1"}]}`}} {
				if _, err := (DashboardReports{}).CreateView(ctx, sc, DashboardViewInput{ID: view.id, OwnerID: "alice", Name: view.id, Preset: "operator", Definition: json.RawMessage(view.definition)}); err != nil {
					return err
				}
			}
			return nil
		})
		if err := publish(tenant, "same-artifact", "same-view", bodies[i], false); err != nil {
			t.Fatal("complete static chunk publication refused", err)
		}
		if err := publish(tenant, "source-downgrade", "source-view", bodies[i], false); err == nil {
			t.Fatal("source-backed view accepted source-free static artifact")
		}
	}
	for _, storage := range []string{"chunks", "document-chunks"} {
		var capture []byte
		if storage == "document-chunks" {
			capture, _ = json.Marshal(map[string]any{"version": 1, "tenant_id": tenants[0]})
		}
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
    (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
    VALUES($1,'invalid-format','same-view','csv','text/csv','bad.csv',NULL,'alice',statement_timestamp()-interval '1 hour',statement_timestamp(),'none',$2,1,decode(repeat('00',32),'hex'),$3::jsonb)`, tenants[0], storage, capture)
			return err
		})
		var shape *pgconn.PgError
		if !errors.As(err, &shape) || shape.Code != "23514" {
			t.Fatal("static/source format lost database capture distinction", storage, err)
		}
	}
	read := func(tenant, id, user string) ([]byte, error) {
		var body []byte
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			meta, stage, err := (DashboardReports{}).StageArtifactBody(ctx, sc, id, user, reporting.BodyStageLimitsForBytes(reporting.DefaultCSVLimits().Bytes))
			if err != nil {
				if stage != nil {
					t.Fatal("failed static read released a partial stage")
				}
				return err
			}
			defer stage.Close()
			if meta.BodyStorage != "document-chunks" {
				t.Fatal("static read representation changed")
			}
			reader, err := stage.Open(ctx)
			if err != nil {
				return err
			}
			defer reader.Close()
			body, err = io.ReadAll(reader)
			return err
		})
		return body, err
	}
	for i, tenant := range tenants {
		body, err := read(tenant, "same-artifact", "alice")
		if err != nil || !bytes.Equal(body, bodies[i]) {
			t.Fatal("complete static body changed or crossed tenant", i, err)
		}
		if body, err := read(tenant, "same-artifact", "bob"); err == nil || len(body) != 0 {
			t.Fatal("foreign owner read static bytes", err)
		}
		err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.report_artifact_format','',true)`); err != nil {
				return err
			}
			var value []byte
			return sc.Q.QueryRow(ctx, `SELECT content FROM dashboard_report_artifacts WHERE id='same-artifact'`).Scan(&value)
		})
		var oldReader *pgconn.PgError
		if !errors.As(err, &oldReader) || oldReader.Code != "0A000" {
			t.Fatal("old reader did not refuse static chunk representation", err)
		}
	}
	if err := publish(tenants[0], "rolled-back", "same-view", bodies[0], true); err == nil {
		t.Fatal("static rollback fixture did not refuse")
	}
	inTenant(ctx, t, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var parents, chunks int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE id IN ('rolled-back','source-downgrade')`).Scan(&parents); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks WHERE artifact_id IN ('rolled-back','source-downgrade')`).Scan(&chunks); err != nil {
			return err
		}
		if parents != 0 || chunks != 0 {
			t.Fatal("static failed publication retained parent/chunk state")
		}
		_, err := sc.Q.Exec(ctx, `DELETE FROM dashboard_report_artifact_chunks WHERE artifact_id='same-artifact' AND ordinal=1`)
		return err
	})
	if body, err := read(tenants[0], "same-artifact", "alice"); !errors.Is(err, ErrReportArtifactIntegrity) || len(body) != 0 {
		t.Fatal("incomplete static body escaped verification", err)
	}
	if body, err := read(tenants[1], "same-artifact", "alice"); err != nil || !bytes.Equal(body, bodies[1]) {
		t.Fatal("static corruption crossed tenant", err)
	}
}
