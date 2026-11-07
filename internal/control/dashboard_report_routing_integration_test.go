// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres source JSONB, chunk writer and body reader.
// Selectors are complete codec fixtures; this proves storage and isolation,
// not an authenticated routing source, report authorization or physical flow.
func TestReportRoutingSourceStorageKeepsWholePeriodsAndTenantAdmission(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	const count = 50_000
	memory := flowstore.DefaultExplorerBudget().MemoryBytes / 4
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		capture := reportRoutingRequirementsFixture(t, tenant, count)
		raw, err := marshalReportSourceRequirements(ctx, capture, memory)
		if err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf("complete source metadata lane %d", lane)
		limits := reporting.BodyStageLimits{Bytes: 1 << 20, MemoryBytes: memory}
		stage, _, err := reporting.StageBody(ctx, tenant, limits, func(w io.Writer) error { _, err := io.WriteString(w, body); return err })
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			repo := store.DashboardReports{}
			if _, err := repo.CreateView(ctx, sc, store.DashboardViewInput{ID: "routing-receipt-view", OwnerID: f.users[tenant], Name: "Routing receipt storage", Preset: "operator", Definition: []byte(`{}`)}); err != nil {
				return err
			}
			input := store.ReportArtifactInput{ID: "routing-receipt-artifact", DashboardID: "routing-receipt-view", GeneratedBy: f.users[tenant], Format: "csv", MediaType: "text/csv", Filename: "routing.csv", AbsoluteFrom: time.Now().Add(-time.Hour), AbsoluteTo: time.Now(), RedactionState: "none"}
			if _, err := repo.CreateChunkedArtifact(ctx, sc, input, stage, raw); err != nil {
				t.Fatal("actual report store refused complete admitted routing source requirements", err)
			}
			return nil
		})
		_ = stage.Close()
		err = tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			repo := store.DashboardReports{}
			metadata, err := repo.GetArtifactMetadata(ctx, sc, "routing-receipt-artifact", f.users[tenant], memory)
			if err != nil {
				return err
			}
			parsed, err := parseReportSourceRequirements(ctx, metadata.SourceCapture, memory)
			if err != nil || !reflect.DeepEqual(parsed.Inputs, capture.Inputs) || metadata.Content != nil {
				t.Fatal("actual report source read lost complete original periods", err)
			}
			var foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id<>$1`, tenant).Scan(&foreign); err != nil {
				return err
			}
			if foreign != 0 {
				t.Fatal("routing report source storage escaped tenant RLS")
			}
			small, err := repo.GetArtifactMetadata(ctx, sc, "routing-receipt-artifact", f.users[tenant], 4096)
			if err != nil || len(small.SourceCapture) != 0 {
				t.Fatal("report metadata fetched an unadmitted source body", err)
			}
			if _, body, err := repo.StageArtifactBody(ctx, sc, "routing-receipt-artifact", f.users[tenant], reporting.BodyStageLimits{Bytes: 1 << 20, MemoryBytes: 4096}); err == nil || body != nil {
				t.Fatal("report body escaped missing source admission", err)
			}
			_, verified, err := repo.StageArtifactBody(ctx, sc, "routing-receipt-artifact", f.users[tenant], limits)
			if err != nil {
				return err
			}
			defer verified.Close()
			reader, err := verified.Open(ctx)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil || string(data) != body {
				t.Fatal("routing source storage changed independent report body", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Log("real-integration: two application-role Postgres lanes with two complete 50000-selector periods each, metadata admission, RLS and verified body; source/actor facts modeled")
}
