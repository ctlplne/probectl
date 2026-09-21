// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDashboardReportTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	now := time.Now().UTC().Truncate(time.Second)
	tenantA, err := NewTenants(pool).Create(ctx, fmt.Sprintf("dashboard-a-%d", now.UnixNano()), "Dashboard A")
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, fmt.Sprintf("dashboard-b-%d", now.UnixNano()), "Dashboard B")
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	definition := []byte(fmt.Sprintf(`{
		"absolute_from":%q,"absolute_to":%q,"provenance":["API"],
		"redaction_state":"secrets removed","coverage_limitations":["offline agents omitted"],
		"metrics":{"Active tests":"3"}}`, now.Add(-time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)))

	inTenant(ctx, t, pool, tenantA.ID, func(ctx context.Context, sc tenancy.Scope) error {
		view, err := (DashboardReports{}).CreateView(ctx, sc, DashboardViewInput{
			ID: "view-a", OwnerID: "alice", Name: "A posture", Preset: "operator",
			Shared: false, Definition: definition,
		})
		if err != nil {
			t.Fatalf("create A dashboard: %v", err)
		}
		if view.TenantID != tenantA.ID {
			t.Fatalf("created dashboard tenant = %s, want %s", view.TenantID, tenantA.ID)
		}
		scheduleID := "schedule-a"
		if _, err := (DashboardReports{}).CreateSchedule(ctx, sc, ReportScheduleInput{
			ID: scheduleID, DashboardID: view.ID, OwnerID: "alice", Name: "Daily A",
			Format: "pdf", Cadence: "daily", DestinationID: "tenant-report-inbox",
			NextRunAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("create A schedule: %v", err)
		}
		if _, err := (DashboardReports{}).CreateArtifact(ctx, sc, ReportArtifactInput{
			ID: "artifact-a", DashboardID: view.ID, ScheduleID: &scheduleID,
			Format: "csv", MediaType: "text/csv", Filename: "a.csv", Content: []byte("metric,value\n"),
			GeneratedBy: "alice", AbsoluteFrom: now.Add(-time.Hour), AbsoluteTo: now,
			Provenance: []string{"API"}, RedactionState: "secrets removed",
			CoverageLimitations: []string{"offline agents omitted"},
		}); err != nil {
			t.Fatalf("create A artifact: %v", err)
		}
		if _, err := (DashboardReports{}).GetArtifact(ctx, sc, "artifact-a", "alice"); err != nil {
			t.Fatalf("owner read A artifact: %v", err)
		}
		if _, err := (DashboardReports{}).CreateView(ctx, sc, DashboardViewInput{
			ID: "manifest-imported-a", OwnerID: "alice", Name: "Imported A posture",
			Preset: "operator", Shared: false, Definition: definition,
		}); err != nil {
			t.Fatalf("create manifest-imported A dashboard: %v", err)
		}
		if _, err := (DashboardReports{}).GetArtifact(ctx, sc, "artifact-a", "bob"); err != nil {
			if apiErr, ok := apierror.As(err); !ok || apiErr.Kind != apierror.KindNotFound {
				t.Fatalf("same-tenant private artifact read = %v, want NotFound", err)
			}
		} else {
			t.Fatal("same-tenant private artifact read succeeded, want NotFound")
		}
		artifacts, err := (DashboardReports{}).ListArtifacts(ctx, sc, "bob")
		if err != nil || len(artifacts) != 0 {
			t.Fatalf("same-tenant private artifact list = %+v / %v", artifacts, err)
		}
		return nil
	})

	inTenant(ctx, t, pool, tenantB.ID, func(ctx context.Context, sc tenancy.Scope) error {
		for name, get := range map[string]func() error{
			"view": func() error {
				_, err := (DashboardReports{}).GetView(ctx, sc, "view-a", "alice")
				return err
			},
			"manifest-imported view": func() error {
				_, err := (DashboardReports{}).GetView(ctx, sc, "manifest-imported-a", "alice")
				return err
			},
			"artifact": func() error {
				_, err := (DashboardReports{}).GetArtifact(ctx, sc, "artifact-a", "alice")
				return err
			},
		} {
			err := get()
			if apiErr, ok := apierror.As(err); !ok || apiErr.Kind != apierror.KindNotFound {
				t.Fatalf("tenant B %s by A id = %v, want NotFound", name, err)
			}
		}
		views, err := (DashboardReports{}).ListViews(ctx, sc, "alice")
		if err != nil || len(views) != 0 {
			t.Fatalf("tenant B dashboard list = %+v / %v", views, err)
		}
		schedules, err := (DashboardReports{}).ListSchedules(ctx, sc, "alice")
		if err != nil || len(schedules) != 0 {
			t.Fatalf("tenant B schedule list = %+v / %v", schedules, err)
		}
		artifacts, err := (DashboardReports{}).ListArtifacts(ctx, sc, "alice")
		if err != nil || len(artifacts) != 0 {
			t.Fatalf("tenant B artifact list = %+v / %v", artifacts, err)
		}
		return nil
	})
}
