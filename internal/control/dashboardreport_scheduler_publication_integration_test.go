// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual one-connection PG/RLS and competing publication proof. Rendering is
// the existing static CSV renderer; live telemetry, delegated source roles and
// complete Unicode PDF/release output remain separate required proofs.
func TestScheduledDashboardReportsRecheckCapturedStateAndPublishOnce(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	configuration := db.Pool().Config()
	configuration.MaxConns, configuration.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tenants := []string{freshTenant(t, db, "scheduled-publication-a"), freshTenant(t, db, "scheduled-publication-b")}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("scheduled report fixture cleanup failed")
		}
	})
	owner, scheduler := uuid(t), uuid(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	dueAt := now.Add(-time.Hour)
	definition, err := json.Marshal(validDashboardRequest().Definition)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	build := func(t *testing.T) *DashboardReportSupervisor {
		t.Helper()
		supervisor, ok := BuildDashboardReportSupervisor(pool, time.Minute, nil)
		if !ok {
			t.Fatal("scheduled report supervisor unavailable")
		}
		return supervisor
	}
	create := func(t *testing.T, viewID, scheduleID string) {
		t.Helper()
		for _, tenant := range tenants {
			if err := mutate(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{
					ID: viewID, OwnerID: owner, Name: "Schedule " + tenant, Preset: "operator", Shared: true, Definition: definition,
				}); err != nil {
					return err
				}
				_, err := (store.DashboardReports{}).CreateSchedule(ctx, sc, store.ReportScheduleInput{
					ID: scheduleID, DashboardID: viewID, OwnerID: scheduler, Name: "Current schedule",
					Format: "csv", Cadence: "daily", DestinationID: reportInboxDestination, NextRunAt: dueAt,
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			if _, err := db.Pool().Exec(context.Background(), `DELETE FROM dashboard_views WHERE tenant_id=ANY($1::uuid[]) AND id=$2`, tenants, viewID); err != nil {
				t.Error("scheduled view cleanup failed")
			}
		})
	}
	state := func(t *testing.T, tenant, viewID, scheduleID string) (int, int, *store.ReportSchedule) {
		t.Helper()
		var artifacts, audits int
		var schedule *store.ReportSchedule
		if err := mutate(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			other := tenants[0]
			if tenant == other {
				other = tenants[1]
			}
			var foreignContent int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE strpos(convert_from(content,'UTF8'),$3)=0 OR strpos(convert_from(content,'UTF8'),$4)>0) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND dashboard_id=$2`, tenant, viewID, tenant, other).Scan(&artifacts, &foreignContent); err != nil {
				return err
			}
			if foreignContent != 0 {
				return apierror.Internal("scheduled artifact content crossed its fixture tenant")
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='dashboard.report_delivery'`, tenant).Scan(&audits); err != nil {
				return err
			}
			var item store.ReportSchedule
			err := sc.Q.QueryRow(ctx, `SELECT owner_id,enabled,next_run_at,last_run_at FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`, tenant, scheduleID).Scan(&item.OwnerID, &item.Enabled, &item.NextRunAt, &item.LastRunAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			schedule = &item
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return artifacts, audits, schedule
	}
	for _, scenario := range []string{"success", "pause", "reschedule", "owner-change", "definition-change", "withdraw-sharing", "deleted", "canceled", "render-failed", "audit-failed"} {
		t.Run(scenario, func(t *testing.T) {
			viewID, scheduleID := uuid(t), uuid(t)
			create(t, viewID, scheduleID)
			var fault string
			if scenario == "audit-failed" {
				fault = "scheduled_report_" + strings.ReplaceAll(uuid(t), "-", "")
				if _, err := db.Pool().Exec(ctx, `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='`+tenants[0]+`'::uuid AND NEW.action='dashboard.report_delivery' THEN RAISE EXCEPTION 'QA scheduled audit refused'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := db.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`() `); err != nil {
						t.Error("scheduled audit fault cleanup failed")
					}
				})
			}
			_, before, _ := state(t, tenants[0], viewID, scheduleID)
			supervisor := build(t)
			runContext, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			calls := 0
			supervisor.render = func(ctx context.Context, format string, document reporting.Document) ([]byte, string, error) {
				calls++
				if document.TenantScope != tenants[0] || document.Title != "Schedule "+tenants[0] {
					t.Fatal("scheduled renderer received foreign captured data")
				}
				// One connection still proves rendering released its capture
				// transaction. Allow bounded runner load without a 1s speed gate.
				databaseContext, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				if err := mutate(databaseContext, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := sc.Q.Exec(ctx, `SELECT 1`); err != nil {
						return err
					}
					var sql string
					switch scenario {
					case "pause":
						sql = `UPDATE dashboard_report_schedules SET enabled=false WHERE tenant_id=$1 AND id=$2`
					case "reschedule":
						sql = `UPDATE dashboard_report_schedules SET next_run_at=next_run_at+interval '2 days' WHERE tenant_id=$1 AND id=$2`
					case "owner-change":
						sql = `UPDATE dashboard_report_schedules SET owner_id='changed-owner' WHERE tenant_id=$1 AND id=$2`
					case "definition-change":
						_, err := sc.Q.Exec(ctx, `UPDATE dashboard_views SET name='changed without clock bump' WHERE tenant_id=$1 AND id=$2`, tenants[0], viewID)
						return err
					case "withdraw-sharing":
						_, err := sc.Q.Exec(ctx, `UPDATE dashboard_views SET shared=false WHERE tenant_id=$1 AND id=$2`, tenants[0], viewID)
						return err
					case "deleted":
						sql = `DELETE FROM dashboard_report_schedules WHERE tenant_id=$1 AND id=$2`
					}
					if sql != "" {
						_, err := sc.Q.Exec(ctx, sql, tenants[0], scheduleID)
						return err
					}
					return nil
				}); err != nil {
					return nil, "", err
				}
				if scenario == "canceled" {
					cancel()
				}
				if scenario == "render-failed" {
					return nil, "", errors.New("QA scheduled renderer refused")
				}
				return renderReport(format, document)
			}
			err := supervisor.materializeTenantReports(runContext, tenants[0], now)
			artifacts, audits, schedule := state(t, tenants[0], viewID, scheduleID)
			if calls != 1 {
				t.Fatal("scheduled renderer did not execute exactly once", calls)
			}
			if scenario == "success" {
				if err != nil || artifacts != 1 || audits != before+1 || schedule == nil || schedule.LastRunAt == nil || !schedule.LastRunAt.Equal(now) || !schedule.NextRunAt.After(now) {
					t.Fatalf("single-connection scheduled report did not publish and advance atomically: artifacts=%d audits=%d error=%v", artifacts, audits-before, err)
				}
				if err := supervisor.materializeTenantReports(runContext, tenants[0], now); err != nil || calls != 1 {
					t.Fatal("consumed due state was rendered again", err)
				}
			} else {
				if artifacts != 0 || audits != before || (schedule != nil && schedule.LastRunAt != nil) {
					t.Fatalf("stale/failed scheduled report published or advanced: artifacts=%d audits=%d error=%v", artifacts, audits-before, err)
				}
				failure := scenario == "canceled" || scenario == "render-failed" || scenario == "audit-failed"
				if (err != nil) != failure {
					t.Fatalf("wrong scheduled refusal outcome: error=%v expected_failure=%t", err, failure)
				}
				if scenario == "canceled" && !errors.Is(err, context.Canceled) {
					t.Fatal("scheduled cancellation was lost", err)
				}
				if scenario == "audit-failed" && (schedule == nil || !schedule.NextRunAt.Equal(dueAt)) {
					t.Fatal("failed scheduled audit consumed its due state")
				}
			}
			if err := build(t).materializeTenantReports(ctx, tenants[1], now); err != nil {
				t.Fatal("tenant A refusal blocked the healthy sibling", err)
			}
			if artifacts, _, schedule := state(t, tenants[1], viewID, scheduleID); artifacts != 1 || schedule == nil || schedule.LastRunAt == nil {
				t.Fatal("equal-ID sibling schedule did not publish independently")
			}
			if scenario == "audit-failed" {
				if _, err := db.Pool().Exec(ctx, `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`() `); err != nil {
					t.Fatal(err)
				}
				if err := build(t).materializeTenantReports(ctx, tenants[0], now); err != nil {
					t.Fatal("rolled-back scheduled report could not retry", err)
				}
				if artifacts, audits, schedule := state(t, tenants[0], viewID, scheduleID); artifacts != 1 || audits != before+1 || schedule == nil || schedule.LastRunAt == nil || !schedule.NextRunAt.After(now) {
					t.Fatal("scheduled audit recovery duplicated or lost the original due state")
				}
			}
		})
	}
	t.Run("private-before-capture", func(t *testing.T) {
		viewID, scheduleID := uuid(t), uuid(t)
		create(t, viewID, scheduleID)
		if err := mutate(ctx, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE dashboard_views SET shared=false WHERE tenant_id=$1 AND id=$2`, tenants[0], viewID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		supervisor := build(t)
		supervisor.render = func(context.Context, string, reporting.Document) ([]byte, string, error) {
			t.Fatal("inaccessible scheduled dashboard reached rendering")
			return nil, "", nil
		}
		if err := supervisor.materializeTenantReports(ctx, tenants[0], now); err != nil {
			t.Fatal(err)
		}
		if artifacts, _, schedule := state(t, tenants[0], viewID, scheduleID); artifacts != 0 || schedule == nil || schedule.LastRunAt != nil {
			t.Fatal("inaccessible scheduled capture published or advanced")
		}
	})
	t.Run("concurrent-workers", func(t *testing.T) {
		viewID, scheduleID := uuid(t), uuid(t)
		create(t, viewID, scheduleID)
		_, before, _ := state(t, tenants[0], viewID, scheduleID)
		supervisor := build(t)
		runContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		arrivals, start, results := make(chan struct{}, 2), make(chan struct{}), make(chan error, 2)
		supervisor.render = func(ctx context.Context, format string, document reporting.Document) ([]byte, string, error) {
			select {
			case arrivals <- struct{}{}:
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
			select {
			case <-start:
				return renderDashboardReport(ctx, format, document)
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		}
		for range 2 {
			go func() { results <- supervisor.materializeTenantReports(runContext, tenants[0], now) }()
		}
		for range 2 {
			select {
			case <-arrivals:
			case <-runContext.Done():
				t.Fatal("competing renderers held a capture transaction", runContext.Err())
			}
		}
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal("competing scheduled publication failed", err)
			}
		}
		if len(arrivals) != 0 {
			t.Fatal("one captured due state caused unexpected extra rendering")
		}
		if artifacts, audits, schedule := state(t, tenants[0], viewID, scheduleID); artifacts != 1 || audits != before+1 || schedule == nil || schedule.LastRunAt == nil || !schedule.NextRunAt.After(now) {
			t.Fatal("same observed due state published more than once or failed to advance")
		}
	})
	t.Run("foreign-capture", func(t *testing.T) {
		viewID, scheduleID := uuid(t), uuid(t)
		create(t, viewID, scheduleID)
		var foreign store.DueDashboardReport
		if err := mutate(ctx, tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
			items, err := (store.DashboardReports{}).ListDueForRendering(ctx, sc, now, 20)
			if err != nil || len(items) != 1 {
				return apierror.Internal("foreign capture fixture unavailable").Wrap(err)
			}
			foreign = items[0]
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := mutate(ctx, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
			out, err := (store.DashboardReports{}).TryClaimDueForPublication(ctx, sc, foreign.Schedule, now)
			if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindForbidden || out != nil {
				t.Fatal("store claimed a foreign captured schedule", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		out, err := build(t).materializeCapturedReport(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), "foreign", foreign, now)
		if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindForbidden || out {
			t.Fatal("supervisor published a foreign capture", err)
		}
		for _, tenant := range tenants {
			if artifacts, _, schedule := state(t, tenant, viewID, scheduleID); artifacts != 0 || schedule == nil || schedule.LastRunAt != nil {
				t.Fatal("foreign capture changed a tenant's artifact or due state")
			}
		}
	})
}
