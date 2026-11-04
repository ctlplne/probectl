// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSubjectErasureInvalidatesOpaqueReportChunksOnlyInTenant(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "report-subject-a-"+stamp), mkTenant(t, pool, "report-subject-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	subject := "erased-report-reader@example.test"
	for _, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_views(tenant_id,id,owner_id,name,preset,definition) VALUES($1,'same-view','another-owner','Report view','operator','{}')`, tenant); err != nil {
				return err
			}
			for _, id := range []string{"own-export", "other-derived"} {
				generator := "another-owner"
				if id == "own-export" {
					generator = subject
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts
     (tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state,body_storage,body_bytes,body_digest,source_capture)
     VALUES($1,$2,'same-view','csv','text/csv','owned.csv',NULL,$3,statement_timestamp()-interval '1 hour',statement_timestamp(),'none','chunks',4,decode(repeat('00',32),'hex'),jsonb_build_object('version',1,'tenant_id',$1::text))`, tenant, id, generator); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,$2,0,$3)`, tenant, id, []byte("body")); err != nil {
					return err
				}
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO dashboard_report_artifacts(tenant_id,id,dashboard_id,format,media_type,filename,content,generated_by,absolute_from,absolute_to,redaction_state) VALUES($1,'legacy-other','same-view','csv','text/csv','legacy.csv',$2,'another-owner',statement_timestamp()-interval '1 hour',statement_timestamp(),'none')`, tenant, []byte("legacy bytes"))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "test backups expire", nil)
	var bundle bytes.Buffer
	if _, err := engine.ExportSubject(ctx, tenants[0], subject, &bundle, false); err != nil {
		t.Fatal("export report subject", err)
	}
	files := readTarGz(t, bundle.Bytes())
	parents := files["postgres/dashboard_report_artifacts.jsonl"]
	children := files["postgres/dashboard_report_artifact_chunks.jsonl"]
	for _, raw := range []string{parents, children} {
		if !strings.Contains(raw, "own-export") || strings.Contains(raw, "other-derived") || strings.Contains(raw, tenants[1]) {
			t.Fatal("subject export broadened beyond owned report parent", raw)
		}
	}
	report, err := engine.EraseSubject(ctx, tenants[0], subject, "privacy-admin", "dsar")
	if err != nil || !report.Complete {
		t.Fatalf("opaque report subject erasure incomplete: %v %+v", err, report)
	}
	planes := subjectPlanesByName(report.Planes)
	if p := planes["postgres:dashboard_report_artifacts"]; p.Status != SubjectStatusDeleted || p.Deleted != 2 || p.Remaining != 0 || !strings.Contains(p.Notes, "all source-aware derived reports") {
		t.Fatal("derived report invalidation impact absent", p)
	}
	if p := planes["postgres:dashboard_report_artifact_chunks"]; p.Status != SubjectStatusDeleted || p.Remaining != 0 {
		t.Fatal("chunk residue was not verified", p)
	}
	for i, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var chunks, parents int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks`).Scan(&chunks); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts`).Scan(&parents); err != nil {
				return err
			}
			wantChunks, wantParents := 0, 1
			if i == 1 {
				wantChunks, wantParents = 2, 3
			}
			if chunks != wantChunks || parents != wantParents {
				t.Fatalf("tenant-local erasure count chunks=%d/%d parents=%d/%d", chunks, wantChunks, parents, wantParents)
			}
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT content FROM dashboard_report_artifacts WHERE id='legacy-other'`).Scan(&body); err != nil {
				return err
			}
			if string(body) != "legacy bytes" {
				t.Fatal("unrelated legacy report changed")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
