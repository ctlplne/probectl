// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const dashboardReportSchedulerActor = "probectl-report-scheduler"

// DashboardReportSupervisor materializes due PDF/CSV schedules into each
// tenant's local report inbox. It enumerates only tenant registry metadata,
// then captures and publishes work in distinct FORCE-RLS transactions per
// tenant. Rendering holds no database transaction or schedule lock.
type DashboardReportSupervisor struct {
	pool         *pgxpool.Pool
	sourceServer *Server
	interval     time.Duration
	log          *slog.Logger
	now          func() time.Time
	render       dashboardReportRenderer
	stage        dashboardReportStager
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
	return &DashboardReportSupervisor{pool: pool, interval: interval, log: log, now: time.Now, render: renderDashboardReport}, true
}

// WithReportSources reuses the existing server's tenant-scoped source services.
// No independent query plane or background credential is constructed.
func (s *DashboardReportSupervisor) WithReportSources(server *Server) *DashboardReportSupervisor {
	if s != nil && server != nil && server.pool == s.pool {
		s.sourceServer = server
		s.stage = stageStaticDashboardReport
	}
	return s
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
		err := errors.Join(s.materializeTenantReports(ctx, tenant.ID, now), s.deliverTenantReportEmails(ctx, tenant.ID, now))
		if err != nil {
			// Tenant id is routing metadata, not report content. Never log the
			// saved view, exact values, or artifact bytes.
			reason := "unavailable"
			if domain, ok := apierror.As(err); ok {
				reason = domain.Code
			}
			s.log.Warn("dashboard report delivery failed", "tenant_id", tenant.ID, "reason", reason)
		}
	}
}

func (s *DashboardReportSupervisor) materializeTenantReports(ctx context.Context, tenantID string, now time.Time) error {
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var due []store.DueDashboardReport
	var tenantName string
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		due, err = (store.DashboardReports{}).ListDueForRendering(ctx, sc, now, 20)
		if err != nil || len(due) == 0 {
			return err
		}
		tenantName, err = dashboardTenantName(ctx, sc)
		return err
	}); err != nil {
		return err
	}
	var failures error
	for _, item := range due {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		_, err := s.materializeCapturedReport(ctx, tenantName, item, now)
		failures = errors.Join(failures, err)
	}
	return failures
}

func (s *DashboardReportSupervisor) materializeCapturedReport(ctx context.Context, tenantName string, item store.DueDashboardReport, now time.Time) (bool, error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || item.Schedule.TenantID != tenant.String() || item.View.TenantID != tenant.String() || item.Schedule.DashboardID != item.View.ID {
		return false, apierror.Forbidden("report publication tenant scope differs")
	}
	if s.render == nil && s.stage == nil {
		return false, apierror.Unavailable("scheduled report renderer is unavailable")
	}
	if item.Schedule.DestinationID != reportInboxDestination {
		if s.sourceServer == nil {
			return false, apierror.Unavailable("report destination services unavailable")
		}
		if err := s.sourceServer.validateReportDestination(tenant.String(), item.Schedule.DestinationID); err != nil {
			return false, err
		}
	}
	var definition dashboardDefinition
	if err := json.Unmarshal(item.View.Definition, &definition); err != nil {
		return false, apierror.Internal("stored scheduled dashboard definition is invalid").Wrap(err)
	}
	if err := cleanDashboardDefinition(&definition); err != nil {
		return false, err
	}
	if item.Schedule.ProviderRequestID != nil && (!item.Schedule.ProviderTriggerAllowed || definition.ClientReport == nil) {
		return false, apierror.Forbidden("provider report consent is no longer applicable")
	}
	if len(definition.FlowSources) > 0 || definition.ClientReport != nil {
		return s.materializeSourceReport(ctx, tenantName, item, definition, now)
	}
	document := reporting.Document{
		Title: item.View.Name, Preset: item.View.Preset, TenantName: tenantName,
		TenantScope: tenant.String(), AbsoluteFrom: definition.AbsoluteFrom,
		AbsoluteTo: definition.AbsoluteTo, GeneratedAt: now,
		GeneratedBy: dashboardReportSchedulerActor, Provenance: definition.Provenance,
		RedactionState:      definition.RedactionState,
		CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics,
	}
	profile, err := (*Server)(nil).staticReportOperation()
	if s.sourceServer != nil {
		profile, err = s.sourceServer.staticReportOperation()
	}
	if err != nil {
		return false, err
	}
	operation, cancel := profile.context(ctx)
	ctx = operation
	defer cancel()
	if s.sourceServer != nil && s.sourceServer.fairnessGate != nil {
		release, err := s.sourceServer.fairnessGate.BeginQuery(ctx, tenant.String())
		if err != nil {
			return false, err
		}
		defer release()
	}
	stager := s.stage
	if stager == nil {
		stager = func(ctx context.Context, format string, doc reporting.Document) (*reporting.BodyStage, string, error) {
			return stageLegacyDashboardReport(ctx, format, doc, s.render)
		}
	}
	stage, mediaType, err := stager(ctx, item.Schedule.Format, document)
	if err != nil {
		return false, err
	}
	defer func() { _ = stage.Close() }()
	receipt, err := stage.Receipt(ctx)
	if err != nil {
		return false, err
	}
	content, err := inlineDashboardStage(ctx, stage)
	if err != nil {
		return false, err
	}
	defer clear(content)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	next, err := nextDashboardReportRun(item.Schedule.Cadence, item.Schedule.NextRunAt, now)
	if err != nil {
		return false, err
	}
	artifactID, err := crypto.UUIDv4()
	if err != nil {
		return false, err
	}
	published := false
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant.String()); err != nil {
			return err
		}
		// Lock the parent before the schedule, matching deletion's order. A
		// revoked share is a discarded capture, never authority to publish.
		view, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, item.View.ID, item.Schedule.OwnerID)
		if domain, ok := apierror.As(err); ok && domain.Kind == apierror.KindNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		if !dashboardReportViewMatches(&item.View, view) {
			return nil
		}
		current, err := (store.DashboardReports{}).TryClaimDueForPublication(ctx, sc, item.Schedule, now)
		if err != nil {
			return err
		}
		if current == nil || !dashboardReportScheduleMatches(item.Schedule, *current) {
			return nil
		}
		scheduleID := item.Schedule.ID
		input := store.ReportArtifactInput{
			ID: artifactID, DashboardID: item.View.ID, ScheduleID: &scheduleID,
			Format: item.Schedule.Format, MediaType: mediaType,
			Filename: reportFilename(item.View.Name, item.Schedule.Format, now), Content: content,
			GeneratedBy: dashboardReportSchedulerActor, AbsoluteFrom: definition.AbsoluteFrom,
			AbsoluteTo: definition.AbsoluteTo, Provenance: definition.Provenance,
			RedactionState:      definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations,
		}
		if receipt.Bytes > maxInlineReportBytes {
			if _, err := (store.DashboardReports{}).CreateDocumentChunkedArtifact(ctx, sc, input, stage); err != nil {
				return err
			}
		} else if _, err := (store.DashboardReports{}).CreateArtifact(ctx, sc, input); err != nil {
			return err
		}
		if item.Schedule.DestinationID != reportInboxDestination {
			if err := (store.DashboardReports{}).QueueReportEmail(ctx, sc, artifactID, item.Schedule.DestinationID); err != nil {
				return err
			}
		}
		if err := (store.DashboardReports{}).MarkScheduleDelivered(ctx, sc, item.Schedule.ID, now, next); err != nil {
			return err
		}
		if _, err := audit.TenantAppend(ctx, sc, dashboardReportSchedulerActor,
			"dashboard.report_delivery", artifactID, map[string]any{
				"dashboard_id": item.View.ID, "schedule_id": item.Schedule.ID,
				"format": item.Schedule.Format, "destination_id": item.Schedule.DestinationID,
				"redaction_state": definition.RedactionState,
				"body_bytes":      receipt.Bytes, "body_sha256": receipt.SHA256,
			}); err != nil {
			return err
		}
		published = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return published, nil
}

func dashboardReportScheduleMatches(captured, current store.ReportSchedule) bool {
	lastRunMatches := captured.LastRunAt == nil && current.LastRunAt == nil
	if captured.LastRunAt != nil && current.LastRunAt != nil {
		lastRunMatches = captured.LastRunAt.Equal(*current.LastRunAt)
	}
	return captured.ID == current.ID && captured.TenantID == current.TenantID &&
		captured.DashboardID == current.DashboardID && captured.OwnerID == current.OwnerID &&
		captured.Name == current.Name && captured.Format == current.Format &&
		captured.Cadence == current.Cadence && captured.DestinationID == current.DestinationID &&
		captured.Enabled == current.Enabled && captured.ProviderTriggerAllowed == current.ProviderTriggerAllowed && reportProviderOriginMatches(captured, current) && captured.NextRunAt.Equal(current.NextRunAt) &&
		captured.CreatedAt.Equal(current.CreatedAt) && captured.UpdatedAt.Equal(current.UpdatedAt) && lastRunMatches
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

func reportProviderOriginMatches(a, b store.ReportSchedule) bool {
	if (a.ProviderRequestID == nil) != (b.ProviderRequestID == nil) || (a.ProviderOriginalNextRunAt == nil) != (b.ProviderOriginalNextRunAt == nil) {
		return false
	}
	if a.ProviderRequestID != nil && *a.ProviderRequestID != *b.ProviderRequestID {
		return false
	}
	return a.ProviderOriginalNextRunAt == nil || a.ProviderOriginalNextRunAt.Equal(*b.ProviderOriginalNextRunAt)
}

func nextSourceReportRun(schedule store.ReportSchedule, now time.Time) (time.Time, error) {
	anchor := schedule.NextRunAt
	if schedule.ProviderOriginalNextRunAt != nil {
		anchor = *schedule.ProviderOriginalNextRunAt
	}
	return nextDashboardReportRun(schedule.Cadence, anchor, now)
}
