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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Complete synthetic CSV bodies prove format/lifecycle behavior, independently
// of the rendered multilingual PDF service proof.
func TestStaticDocumentChunksSubjectPortabilityErasureAndSiblingSurvival(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := time.Now().UnixNano()
	tenants := []string{mkTenant(t, pool, fmt.Sprintf("static-subject-a-%d", stamp)), mkTenant(t, pool, fmt.Sprintf("static-subject-b-%d", stamp))}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	const subject = "static-report-reader@example.test"
	bodies := make([][]byte, 2)
	for lane, tenant := range tenants {
		bodies[lane] = bytes.Repeat([]byte(fmt.Sprintf("private-static-lane%d,9007199254740993\r\n", lane)), 70001)
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		stage, _, err := reporting.StageBody(bound, tenant, reporting.DefaultBodyStageLimits(), func(w io.Writer) error { _, err := w.Write(bodies[lane]); return err })
		if err != nil {
			t.Fatal(err)
		}
		err = tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "same-static-view", OwnerID: "another-owner", Name: "Static documents", Preset: "operator", Definition: json.RawMessage(`{}`)}); err != nil {
				return err
			}
			if _, err := (store.DashboardReports{}).CreateSchedule(ctx, sc, store.ReportScheduleInput{ID: "same-static-schedule", DashboardID: "same-static-view", OwnerID: subject, Name: "Static schedule", Format: "csv", Cadence: "daily", DestinationID: "tenant-report-inbox", NextRunAt: time.Now().Add(time.Hour)}); err != nil {
				return err
			}
			for _, id := range []string{"owned-document", "owned-static-schedule", "unrelated-document"} {
				in := store.ReportArtifactInput{ID: id, DashboardID: "same-static-view", Format: "csv", MediaType: "text/csv", Filename: "complete.csv", GeneratedBy: "another-owner", AbsoluteFrom: time.Now().Add(-time.Hour), AbsoluteTo: time.Now(), RedactionState: "none"}
				if id == "owned-document" {
					in.GeneratedBy = subject
				}
				if id == "owned-static-schedule" {
					schedule := "same-static-schedule"
					in.ScheduleID, in.GeneratedBy = &schedule, "probectl-report-scheduler"
				}
				if _, err := (store.DashboardReports{}).CreateDocumentChunkedArtifact(ctx, sc, in, stage); err != nil {
					return err
				}
			}
			return nil
		})
		_ = stage.Close()
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
		t.Fatal(err)
	}
	files := readTarGz(t, bundle.Bytes())
	parents := files["postgres/dashboard_report_artifacts.jsonl"]
	if !strings.Contains(parents, "owned-document") || !strings.Contains(parents, "owned-static-schedule") || strings.Contains(parents, "unrelated-document") || strings.Contains(parents, tenants[1]) {
		t.Fatal("static subject portability omitted owned parents or exposed unrelated metadata")
	}
	exported := map[string][][]byte{}
	decoder := json.NewDecoder(bytes.NewBufferString(files["postgres/dashboard_report_artifact_chunks.jsonl"]))
	for {
		var row struct {
			Tenant  string `json:"tenant_id"`
			ID      string `json:"artifact_id"`
			Ordinal int    `json:"ordinal"`
			Content string `json:"content"`
		}
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if row.Tenant != tenants[0] || (row.ID != "owned-document" && row.ID != "owned-static-schedule") || len(row.Content) < 2 || row.Content[:2] != `\x` {
			t.Fatal("static subject portability included unrelated bytes")
		}
		body, err := hex.DecodeString(row.Content[2:])
		if err != nil || row.Ordinal < 0 {
			t.Fatal("static subject portability corrupted a chunk", err)
		}
		for len(exported[row.ID]) <= row.Ordinal {
			exported[row.ID] = append(exported[row.ID], nil)
		}
		if exported[row.ID][row.Ordinal] != nil {
			t.Fatal("static subject portability duplicated a chunk")
		}
		exported[row.ID][row.Ordinal] = body
	}
	for _, id := range []string{"owned-document", "owned-static-schedule"} {
		if !bytes.Equal(bytes.Join(exported[id], nil), bodies[0]) {
			t.Fatal("static subject portability omitted complete owned body", id)
		}
	}
	if report, err := engine.EraseSubject(ctx, tenants[0], subject, "privacy-admin", "dsar"); err != nil || !report.Complete {
		t.Fatal("static subject erasure incomplete", err)
	}
	for lane, tenant := range tenants {
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var parents int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts`).Scan(&parents); err != nil {
				return err
			}
			want := 3
			if lane == 0 {
				want = 1
			}
			if parents != want {
				t.Fatal("static erasure changed unrelated or foreign parents", lane, parents, want)
			}
			for _, id := range []string{"owned-document", "owned-static-schedule", "unrelated-document"} {
				if lane == 0 && id != "unrelated-document" {
					continue
				}
				_, stage, err := (store.DashboardReports{}).StageArtifactBody(ctx, sc, id, "another-owner", reporting.DefaultBodyStageLimits())
				if err != nil {
					return err
				}
				defer stage.Close()
				reader, err := stage.Open(ctx)
				if err != nil {
					return err
				}
				body, err := io.ReadAll(reader)
				closed := reader.Close()
				if err != nil {
					return err
				}
				if closed != nil {
					return closed
				}
				if !bytes.Equal(body, bodies[lane]) {
					t.Fatal("static erasure removed unrelated or foreign complete bytes", lane, id)
				}
			}
			return nil
		}); err != nil {
			t.Fatal("static surviving document is unreadable", err)
		}
	}
}
