// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *DashboardReportSupervisor) materializeSourceReport(ctx context.Context, tenantName string, item store.DueDashboardReport, definition dashboardDefinition, now time.Time) (bool, error) {
	server := s.sourceServer
	if server == nil {
		return false, apierror.Unavailable("scheduled report source services are unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(server.flowStore)
	if err := budget.Validate(); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	current, err := loadCurrentUserAuthority(ctx, s.pool, item.Schedule.TenantID, item.Schedule.OwnerID)
	if err != nil {
		return false, err
	}
	ctx, actor, err := current.backgroundContext(ctx, []string{"metrics.read", permAIQuery, permFlowRead, permTagsRead, "agent.read", "entities.read"})
	if err != nil {
		return false, err
	}
	resource := map[string]string{auth.ResourceTenantKey: actor.TenantID}
	if err := server.authorize(ctx, actor, "metrics.read", auth.RBACGlobal, resource); err != nil {
		return false, err
	}
	capture, err := server.captureReportFlowSources(ctx, actor, definition.FlowSources)
	if err != nil {
		return false, err
	}
	defer capture.Close()
	document, err := sourceReportDocument(&item.View, definition, tenantName, dashboardReportSchedulerActor, now, capture)
	if err != nil {
		return false, err
	}
	requirements, err := marshalReportSourceRequirements(ctx, capture)
	if err != nil {
		return false, err
	}
	stage, mediaType, err := stageSourceDashboardReport(ctx, item.Schedule.Format, document, budget, server.reportOutputPolicy())
	if err != nil {
		return false, err
	}
	defer func() { _ = stage.Close() }()
	next, err := nextDashboardReportRun(item.Schedule.Cadence, item.Schedule.NextRunAt, now)
	if err != nil {
		return false, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return false, err
	}
	published := false
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
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
		schedule, err := (store.DashboardReports{}).TryClaimDueForPublication(ctx, sc, item.Schedule, now)
		if err != nil {
			return err
		}
		if schedule == nil || !dashboardReportScheduleMatches(item.Schedule, *schedule) {
			return nil
		}
		if err := server.validateReportSourcePublication(ctx, sc, actor, capture); err != nil {
			return err
		}
		scheduleID := schedule.ID
		artifact, err := (store.DashboardReports{}).CreateChunkedArtifact(ctx, sc, sourceReportArtifactInput(id, &scheduleID, view, schedule.Format, mediaType, document), stage, requirements)
		if err != nil {
			return err
		}
		if err := (store.DashboardReports{}).MarkScheduleDelivered(ctx, sc, schedule.ID, now, next); err != nil {
			return err
		}
		if _, err := audit.TenantAppend(ctx, sc, dashboardReportSchedulerActor, "dashboard.report_delivery", id, map[string]any{
			"dashboard_id": view.ID, "schedule_id": schedule.ID, "format": schedule.Format,
			"destination_id": reportInboxDestination, "redaction_state": document.RedactionState,
			"body_bytes": artifact.BodyBytes, "body_sha256": artifact.BodySHA256, "source_count": len(definition.FlowSources),
		}); err != nil {
			return err
		}
		published = true
		return nil
	})
	return published, err
}
