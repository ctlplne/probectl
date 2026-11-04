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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportArtifactChunksStageCompleteBodiesAndRefuseCorruption(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	tenants := make([]string, 2)
	payloads := make([][]byte, 2)
	for i := range tenants {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("report-io-%d-%d", i, time.Now().UnixNano()), "Report IO")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
		payloads[i] = bytes.Repeat([]byte(fmt.Sprintf("tenant-%d,precise-value-9007199254740993\r\n", i)), 70001)
		if len(payloads[i]) <= 2<<20 {
			t.Fatal("positive fixture did not exceed legacy body ceiling")
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	input := ReportArtifactInput{ID: "same-artifact", DashboardID: "same-view", Format: "csv", MediaType: "text/csv", Filename: "complete.csv", GeneratedBy: "alice", AbsoluteFrom: time.Now().Add(-time.Hour), AbsoluteTo: time.Now(), RedactionState: "none", Provenance: []string{"owned source"}}
	publish := func(tenant, id string, body []byte, rollback bool) error {
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		stage, _, err := reporting.StageBody(tctx, tenant, reporting.DefaultBodyStageLimits(), func(w io.Writer) error { _, err := w.Write(body); return err })
		if err != nil {
			return err
		}
		defer stage.Close()
		capture, _ := json.Marshal(map[string]any{"version": 1, "tenant_id": tenant})
		in := input
		in.ID = id
		return tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			meta, err := (DashboardReports{}).CreateChunkedArtifact(ctx, sc, in, stage, capture)
			if err != nil {
				return err
			}
			if meta.Content != nil || meta.BodyBytes != int64(len(body)) || len(meta.BodySHA256) != 64 {
				t.Fatal("chunk publication loaded bytes or lost sealed integrity metadata")
			}
			if _, err := audit.TenantAppend(ctx, sc, "alice", "dashboard.report.generated", id, map[string]any{"format": "csv"}); err != nil {
				return err
			}
			if rollback {
				return errors.New("test audit/publication refusal")
			}
			return nil
		})
	}
	for i, tenant := range tenants {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (DashboardReports{}).CreateView(ctx, sc, DashboardViewInput{ID: "same-view", OwnerID: "alice", Name: "Owned view", Preset: "operator", Definition: []byte(`{}`)}); err != nil {
				return err
			}
			legacy := input
			legacy.ID, legacy.Content = "legacy", []byte("legacy exact Unicode é\r\n")
			_, err := (DashboardReports{}).CreateArtifact(ctx, sc, legacy)
			return err
		})
		if err := publish(tenant, "same-artifact", payloads[i], false); err != nil {
			t.Fatal("complete staged publication", err)
		}
	}
	read := func(tenant, id, user string, limits reporting.BodyStageLimits) (*ReportArtifactMetadata, *reporting.BodyStage, error) {
		var meta *ReportArtifactMetadata
		var stage *reporting.BodyStage
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			meta, stage, err = (DashboardReports{}).StageArtifactBody(ctx, sc, id, user, limits)
			return err
		})
		if err != nil && stage != nil {
			_ = stage.Close()
			t.Fatal("failed read returned a partial stage")
		}
		return meta, stage, err
	}
	for i, tenant := range tenants {
		legacy, legacyStage, err := read(tenant, "legacy", "alice", reporting.DefaultBodyStageLimits())
		if err != nil {
			t.Fatal("legacy inline snapshot read", err)
		}
		legacyReader, err := legacyStage.Open(tenancy.WithTenant(ctx, tenancy.ID(tenant)))
		if err != nil {
			t.Fatal(err)
		}
		legacyBytes, err := io.ReadAll(legacyReader)
		_ = legacyReader.Close()
		_ = legacyStage.Close()
		if err != nil || string(legacyBytes) != "legacy exact Unicode é\r\n" || legacy.BodyStorage != "inline" || len(legacy.BodySHA256) != 64 {
			t.Fatal("legacy body changed through verified reader", err)
		}
		meta, stage, err := read(tenant, "same-artifact", "alice", reporting.DefaultBodyStageLimits())
		if err != nil {
			t.Fatal(err)
		}
		reader, err := stage.Open(tenancy.WithTenant(ctx, tenancy.ID(tenant)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		_ = reader.Close()
		_ = stage.Close()
		if err != nil || !bytes.Equal(got, payloads[i]) || meta.Content != nil || meta.BodyBytes != int64(len(got)) {
			t.Fatal("owned complete chunk body or integrity metadata changed", err)
		}
		if metadata, body, err := read(tenant, "same-artifact", "bob", reporting.DefaultBodyStageLimits()); err == nil || metadata != nil || body != nil {
			t.Fatal("private body escaped same-tenant owner visibility")
		}
	}
	if _, stage, err := read(tenants[0], "same-artifact", "alice", reporting.BodyStageLimits{Bytes: 128, MemoryBytes: 1 << 20}); err == nil || stage != nil {
		t.Fatal("body read ignored caller staging budget")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, stage, err := (DashboardReports{}).StageArtifactBody(ctx, sc, "same-artifact", "alice", reporting.DefaultBodyStageLimits())
		if stage != nil {
			_ = stage.Close()
			t.Fatal("non-snapshot read returned bytes")
		}
		return err
	}); !errors.Is(err, ErrReportArtifactSnapshot) {
		t.Fatal("body read accepted independently changing metadata/chunk snapshots", err)
	}
	if err := publish(tenants[0], "rolled-back", payloads[0], true); err == nil {
		t.Fatal("publication refusal did not abort transaction")
	}
	if _, stage, err := read(tenants[0], "rolled-back", "alice", reporting.DefaultBodyStageLimits()); err == nil || stage != nil {
		t.Fatal("refused publication left a visible body")
	}
	inTenant(ctx, t, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var chunks, audits int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifact_chunks WHERE artifact_id='rolled-back'`).Scan(&chunks); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE target='rolled-back'`).Scan(&audits); err != nil {
			return err
		}
		if chunks != 0 || audits != 0 {
			t.Fatal("refused publication retained chunks or audit", chunks, audits)
		}
		return nil
	})
	for _, scenario := range []string{"missing", "length", "extra", "digest", "ordinal", "total"} {
		t.Run(scenario, func(t *testing.T) {
			if err := publish(tenants[0], scenario, payloads[0], false); err != nil {
				t.Fatal(err)
			}
			query := map[string]string{
				"missing": `DELETE FROM dashboard_report_artifact_chunks WHERE tenant_id=$1 AND artifact_id=$2 AND ordinal=1`,
				"length":  `UPDATE dashboard_report_artifact_chunks SET content='x' WHERE tenant_id=$1 AND artifact_id=$2 AND ordinal=1`,
				"extra":   `INSERT INTO dashboard_report_artifact_chunks(tenant_id,artifact_id,ordinal,content) VALUES($1,$2,100,'x')`,
				"digest":  `UPDATE dashboard_report_artifact_chunks SET content=overlay(content placing decode('ff','hex') from 1 for 1) WHERE tenant_id=$1 AND artifact_id=$2 AND ordinal=1`,
				"ordinal": `UPDATE dashboard_report_artifact_chunks SET ordinal=100 WHERE tenant_id=$1 AND artifact_id=$2 AND ordinal=1`,
				"total":   `UPDATE dashboard_report_artifacts SET body_bytes=body_bytes+1 WHERE tenant_id=$1 AND id=$2`,
			}[scenario]
			if _, err := pool.Exec(ctx, query, tenants[0], scenario); err != nil {
				t.Fatal("test corruption setup", err)
			}
			if metadata, body, err := read(tenants[0], scenario, "alice", reporting.DefaultBodyStageLimits()); !errors.Is(err, ErrReportArtifactIntegrity) || metadata != nil || body != nil {
				t.Fatal("corrupt report exposed metadata or partial bytes", err)
			}
		})
	}
	// A foreign-only ID must be indistinguishable from an unknown artifact.
	if err := publish(tenants[1], "foreign-only", payloads[1], false); err != nil {
		t.Fatal(err)
	}
	if _, stage, err := read(tenants[0], "foreign-only", "alice", reporting.DefaultBodyStageLimits()); err == nil || stage != nil {
		t.Fatal("foreign report body escaped tenant-first storage")
	} else if failure, ok := apierror.As(err); !ok || failure.Kind != apierror.KindNotFound {
		t.Fatal("foreign body exposed another error shape", err)
	}
}
