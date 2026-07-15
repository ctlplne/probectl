// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/reporting"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const dashboardReportSchedulerActor = "probectl-report-scheduler"

// DashboardReportSupervisor materializes due PDF/CSV schedules into each
// tenant's local report inbox. It enumerates only tenant registry metadata,
// then opens a distinct FORCE-RLS transaction per tenant; report data from two
// tenants is never present in the same storage scope or artifact.
type DashboardReportSupervisor struct {
	pool     *pgxpool.Pool
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
}

func BuildDashboardReportSupervisor(pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) (*DashboardReportSupervisor, bool) {
	if pool == nil {
		return nil, false
	}
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &DashboardReportSupervisor{pool: pool, interval: interval, log: log, now: time.Now}, true
}

func (s *DashboardReportSupervisor) Run(ctx context.Context) {
	s.Tick(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

func (s *DashboardReportSupervisor) Tick(ctx context.Context) {
	tenants, err := store.NewTenants(s.pool).List(ctx)
	if err != nil {
		s.log.Warn("dashboard report tenant scan failed", "error", err)
		return
	}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		if tenant.Status != "active" {
			continue
		}
		now := s.now().UTC()
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), s.pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				return materializeDueDashboardReports(ctx, sc, now)
			})
		if err != nil {
			// Tenant id is routing metadata, not report content. Never log the
			// saved view, exact values, or artifact bytes.
			s.log.Warn("dashboard report delivery failed", "tenant_id", tenant.ID, "error", err)
		}
	}
}

func materializeDueDashboardReports(ctx context.Context, sc tenancy.Scope, now time.Time) error {
	due, err := (store.DashboardReports{}).ClaimDue(ctx, sc, now, 20)
	if err != nil {
		return err
	}
	tenantName, err := dashboardTenantName(ctx, sc)
	if err != nil {
		return err
	}
	for _, item := range due {
		if item.Schedule.DestinationID != reportInboxDestination {
			return fmt.Errorf("schedule %s has an unconfigured destination", item.Schedule.ID)
		}
		var definition dashboardDefinition
		if err := json.Unmarshal(item.View.Definition, &definition); err != nil {
			return fmt.Errorf("decode schedule %s dashboard: %w", item.Schedule.ID, err)
		}
		if err := cleanDashboardDefinition(&definition); err != nil {
			return fmt.Errorf("validate schedule %s dashboard: %w", item.Schedule.ID, err)
		}
		artifactID, err := crypto.UUIDv4()
		if err != nil {
			return err
		}
		document := reporting.Document{
			Title: item.View.Name, Preset: item.View.Preset, TenantName: tenantName,
			TenantScope: sc.Tenant.String(), AbsoluteFrom: definition.AbsoluteFrom,
			AbsoluteTo: definition.AbsoluteTo, GeneratedAt: now,
			GeneratedBy: dashboardReportSchedulerActor, Provenance: definition.Provenance,
			RedactionState:      definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics,
		}
		content, mediaType, err := renderReport(item.Schedule.Format, document)
		if err != nil {
			return err
		}
		scheduleID := item.Schedule.ID
		if _, err := (store.DashboardReports{}).CreateArtifact(ctx, sc, store.ReportArtifactInput{
			ID: artifactID, DashboardID: item.View.ID, ScheduleID: &scheduleID,
			Format: item.Schedule.Format, MediaType: mediaType,
			Filename: reportFilename(item.View.Name, item.Schedule.Format, now), Content: content,
			GeneratedBy: dashboardReportSchedulerActor, AbsoluteFrom: definition.AbsoluteFrom,
			AbsoluteTo: definition.AbsoluteTo, Provenance: definition.Provenance,
			RedactionState:      definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations,
		}); err != nil {
			return err
		}
		next, err := nextDashboardReportRun(item.Schedule.Cadence, item.Schedule.NextRunAt, now)
		if err != nil {
			return err
		}
		if err := (store.DashboardReports{}).MarkScheduleDelivered(ctx, sc, item.Schedule.ID, now, next); err != nil {
			return err
		}
		if _, err := audit.TenantAppend(ctx, sc, dashboardReportSchedulerActor,
			"dashboard.report_delivery", artifactID, map[string]any{
				"dashboard_id": item.View.ID, "schedule_id": item.Schedule.ID,
				"format": item.Schedule.Format, "destination_id": reportInboxDestination,
				"redaction_state": definition.RedactionState,
			}); err != nil {
			return err
		}
	}
	return nil
}

func nextDashboardReportRun(cadence string, scheduled, now time.Time) (time.Time, error) {
	next := scheduled.UTC()
	for !next.After(now) {
		switch cadence {
		case "daily":
			next = next.AddDate(0, 0, 1)
		case "weekly":
			next = next.AddDate(0, 0, 7)
		case "monthly":
			next = next.AddDate(0, 1, 0)
		default:
			return time.Time{}, fmt.Errorf("unsupported report cadence %q", cadence)
		}
	}
	return next, nil
}
