// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientAssessmentFindingsKeepExactEvidenceAndTwoTenantScope(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, to, availability, objectives := clientReportTableFixture(tenant)
		availability[0].Counts.Failed = "9007199254740995"
		meets := false
		objectives[0].ObservedMeetsObjective = &meets
		capture := &clientReportCapture{TenantID: tenant, From: from, To: to, Availability: availability, SLOs: objectives,
			Capacity: []clientReportCapacityCapture{{Input: flow.CapacityForecastRequest{CapacityBPS: "1000000000"}, OriginalsDigest: strings.Repeat("a", 64),
				Measurement: flow.CapacityForecastMeasurement{Forecasts: []flow.CapacityForecastResult{{Target: "uplink", Direction: "in", From: from, To: to,
					ObservedExceedances: 3, ExpectedSamples: 4032, ObservedSamples: 2, Reason: "insufficient_observations"}}}}}}
		tables, err := projectClientAssessmentFindings(ctx, capture, 1<<20)
		if err != nil || len(tables) != 2 || tables[0].ExpectedRows != 3 || tables[1].ExpectedRows != 3 {
			t.Fatal("complete assessment findings or known coverage gaps were lost", err)
		}
		capture.Availability[0].Counts.Failed = "0"
		capture.Capacity[0].Input.CapacityBPS = "1"
		for _, table := range tables {
			rows := assessmentFindingRows(ctx, t, table)
			for _, row := range rows {
				if row["tenant_id"] != tenant || row["window_to"] != to.Format(time.RFC3339Nano) || row["originals_digest"] == "" {
					t.Fatal("finding lost its original evidence, window or tenant")
				}
			}
			if table.ID == "assessment-risks" && (rows["failed_test_outcomes"]["observed_value"] != "9007199254740995" || rows["observed_slo_breach"]["window_from"] != objectives[0].From.Format(time.RFC3339Nano) || !strings.Contains(rows["observed_capacity_exceedances"]["comparison_basis"], "capacity_bps=1000000000")) {
				t.Fatal("findings rounded counts, shortened the SLO window or borrowed mutable assumptions")
			}
			if table.ID == "assessment-coverage" && (rows["slo_outcome_unknown"]["observed_value"] != "0/0" || !strings.Contains(rows["synthetic_observation_coverage"]["comparison_basis"], "canceled=1") || rows["capacity_forecast_coverage"]["observed_value"] != "2/4032") {
				t.Fatal("unknown coverage became a healthy outcome or missing capacity samples disappeared")
			}
			foreign := tenancy.WithTenant(t.Context(), tenancy.ID("foreign"))
			called := false
			if err := table.WalkRows(foreign, func([]string) error { called = true; return nil }); !errors.Is(err, entity.ErrScopeMismatch) || called {
				t.Fatal("assessment cursor disclosed another tenant's findings", err)
			}
		}
		capture.SLOs[1].TenantID = "foreign"
		if tables, err := projectClientAssessmentFindings(ctx, capture, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || tables != nil {
			t.Fatal("late foreign evidence returned an apparently publishable findings prefix", err)
		}
	}
}

func TestClientAssessmentFindingsExposeUnconfiguredMeasurementSections(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	from, to, _, _ := clientReportTableFixture(tenant)
	tables, err := projectClientAssessmentFindings(ctx, &clientReportCapture{TenantID: tenant, From: from, To: to}, 1<<20)
	if err != nil || tables[0].ExpectedRows != 0 || tables[1].ExpectedRows != 3 {
		t.Fatal("empty measurement coverage was presented as a healthy assessment", err)
	}
	rows := assessmentFindingRows(ctx, t, tables[1])
	for _, name := range []string{"synthetic_sources_not_configured", "slo_definitions_unavailable", "capacity_targets_not_configured"} {
		if rows[name]["observed_value"] != "0" {
			t.Fatal("unconfigured section has no explicit coverage gap", name)
		}
	}
}

func assessmentFindingRows(ctx context.Context, t *testing.T, table reporting.CSVTable) map[string]map[string]string {
	t.Helper()
	rows := map[string]map[string]string{}
	if err := table.WalkRows(ctx, func(row []string) error {
		values := map[string]string{}
		for i, value := range row {
			values[table.Columns[i].Name] = value
		}
		rows[values["finding"]] = values
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}
