// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalMetricHistoryUsesOwnedSeriesAndCurrentReadAuthority(t *testing.T) {
	proveOwnedSeasonalMetricHistory(t, "", anomaly.WeeklyTrainingWeeks)
}

func TestSeasonalMetricCadencesKeepFullOriginalScopedHistory(t *testing.T) {
	t.Run("hourly", func(t *testing.T) { proveOwnedSeasonalMetricHistory(t, anomaly.SeasonalHourly, 42*24) })
	t.Run("daily", func(t *testing.T) { proveOwnedSeasonalMetricHistory(t, anomaly.SeasonalDaily, 42) })
}

func proveOwnedSeasonalMetricHistory(t *testing.T, cadence anomaly.SeasonalCadence, windowCount int) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	memory := tsdb.NewMemory()
	f.server.WithTSDB(memory).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	model, err := anomaly.NewWeeklySeasonalModel(anomaly.WeeklySeasonalConfig{
		Cadence: cadence, Timezone: "UTC", MinimumDays: 3, MinimumDeviation: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 10, 12, 0, 0, time.UTC)
	const metric = "known_interface_rate"
	var previousContext context.Context
	var previousCredential *auth.Principal
	for lane, tenant := range f.tenants {
		labels := map[string]string{tsdb.TenantLabel: tenant, "node": "shared-display-name"}
		level := 100 + float64(lane)*100
		var points []tsdb.Series
		for _, window := range model.ComparableWindows(at) {
			points = append(points, tsdb.Series{Metric: metric, Labels: labels, TimeMillis: window.Start.Add(time.Second).UnixMilli(), Value: level},
				tsdb.Series{Metric: metric, Labels: labels, TimeMillis: window.End.UnixMilli(), Value: level * 10})
		}
		points = append(points, tsdb.Series{Metric: metric, Labels: labels, TimeMillis: at.UnixMilli(), Value: level + float64(1-lane)*25})
		if err := memory.Write(t.Context(), points); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		owner, err := loadCurrentUserAuthority(ctx, f.pool, tenant, f.users[tenant])
		if err != nil {
			t.Fatal(err)
		}
		ctx, actor, err := owner.backgroundContext(ctx, []string{"metrics.read"})
		if err != nil {
			t.Fatal(err)
		}
		if lane == 0 {
			previousContext, previousCredential = ctx, actor
		}
		rule := alert.Rule{TenantID: tenant, Metric: metric, Type: alert.Baseline, Sensitivity: 3, Match: map[string]string{"node": "shared-display-name"}}
		scores, labels, err := f.server.compareSeasonalMetrics(ctx, actor, rule, model, at, time.Time{})
		if err != nil || len(scores) != 1 || scores[0].State != []anomaly.SeasonalState{anomaly.SeasonalUp, anomaly.SeasonalNormal}[lane] ||
			scores[0].Observed.TenantID != tenant || scores[0].Evidence.Median != 100+float64(lane)*100 ||
			scores[0].TrainingWindow.Samples != windowCount || scores[0].Evidence.Cadence != cadence || labels[scores[0].Observed.Subject][tsdb.TenantLabel] != tenant {
			t.Fatalf("tenant did not receive its own exact calendar history: %+v (%v)", scores, err)
		}
		rule.TenantID = f.tenants[1-lane]
		if scores, _, err := f.server.compareSeasonalMetrics(ctx, actor, rule, model, at, time.Time{}); !errors.Is(err, tenancy.ErrNoTenant) || len(scores) != 0 {
			t.Fatal("foreign rule attempted history with current tenant authorization", err)
		}
	}
	tenant := f.tenants[0]
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'`, tenant, f.roles[tenant])
		return err
	})
	if scores, _, err := f.server.compareSeasonalMetrics(previousContext, previousCredential, alert.Rule{TenantID: tenant, Metric: metric}, model, at, time.Time{}); err == nil || len(scores) != 0 {
		t.Fatal("withdrawn source reader still receives tenant-local seasonal scores")
	}
}
