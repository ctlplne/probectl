// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *DashboardReportSupervisor) materializeProspectAssessment(ctx context.Context, tenant, tenantName string, now time.Time) error {
	server := s.sourceServer
	if server == nil {
		return nil
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	engagement, view, err := s.dueProspectAssessment(ctx, now)
	if err != nil || view == nil {
		return err
	}
	definition, err := prospectAssessmentDefinition(view, engagement)
	if err != nil {
		return err
	}
	budget, err := server.sourceReportBudget()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(server)
	authority, err := loadCurrentUserAuthority(ctx, s.pool, tenant, engagement.OwnerID)
	if err != nil {
		return err
	}
	ctx, actor, err := authority.backgroundContext(ctx, reportBackgroundSourcePermissions())
	if err != nil {
		return err
	}
	if err := server.authorize(ctx, actor, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: tenant}); err != nil {
		return err
	}
	capture, err := server.captureConfiguredReportSources(ctx, actor, definition, now)
	if err != nil {
		return err
	}
	defer capture.Close()
	document, err := sourceReportDocument(view, definition, tenantName, dashboardReportSchedulerActor, now, capture)
	if err != nil {
		return err
	}
	requirements, err := marshalReportSourceRequirements(ctx, capture, budget.MemoryBytes/4)
	if err != nil {
		return err
	}
	const format = "pdf"
	stage, mediaType, err := stageSourceDashboardReport(ctx, format, document, budget, server.reportOutputPolicy())
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }()
	if err := revalidateMonthlyReportOriginals(ctx, capture); err != nil {
		return err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	input := sourceReportArtifactInput(id, nil, view, format, mediaType, document)
	return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		latest, err := (store.ProspectEngagements{}).Get(ctx, sc)
		if err != nil {
			return err
		}
		if latest.Revision != engagement.Revision || latest.ConvertedAt != nil || latest.AssessmentArtifactID != "" {
			return nil
		}
		current, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, view.ID, engagement.OwnerID)
		if err != nil {
			return err
		}
		if !dashboardReportViewMatches(view, current) {
			return apierror.Conflict("the prospect assessment view changed before publication")
		}
		if err := server.validateReportSourcePublication(ctx, sc, actor, capture); err != nil {
			return err
		}
		artifact, err := (store.DashboardReports{}).CreateChunkedArtifact(ctx, sc, input, stage, requirements)
		if err != nil {
			return err
		}
		if err := (store.ProspectEngagements{}).FileAssessment(ctx, sc, engagement.Revision, artifact.ID, now); err != nil {
			return err
		}
		if latest.HasCurrentDeliveryConsent() {
			if err := (store.DashboardReports{}).QueueReportEmail(ctx, sc, artifact.ID, latest.DestinationID); err != nil {
				return err
			}
		}
		return audit.TenantRecord(ctx, sc, dashboardReportSchedulerActor, "lifecycle.prospect_assessment_created", artifact.ID, map[string]any{
			"revision": engagement.Revision, "owner_id": engagement.OwnerID, "body_sha256": artifact.BodySHA256,
			"body_bytes": artifact.BodyBytes, "assessment_view_id": view.ID,
		})
	})
}

func (s *DashboardReportSupervisor) dueProspectAssessment(ctx context.Context, now time.Time) (store.ProspectEngagement, *store.DashboardView, error) {
	var engagement store.ProspectEngagement
	var view *store.DashboardView
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		engagement, err = (store.ProspectEngagements{}).Get(ctx, sc)
		if domain, ok := apierror.As(err); ok && domain.Kind == apierror.KindNotFound {
			return nil
		}
		if err != nil || engagement.EndsAt.After(now) || engagement.ConvertedAt != nil || engagement.AssessmentArtifactID != "" {
			return err
		}
		view, err = (store.DashboardReports{}).GetView(ctx, sc, engagement.AssessmentViewID, engagement.OwnerID)
		return err
	})
	return engagement, view, err
}

func prospectAssessmentDefinition(view *store.DashboardView, engagement store.ProspectEngagement) (dashboardDefinition, error) {
	var def dashboardDefinition
	if view.OwnerID != engagement.OwnerID || !view.UpdatedAt.Equal(engagement.AssessmentAt) {
		return def, apierror.Conflict("the prospect assessment needs the original owned view revision")
	}
	if err := json.Unmarshal(view.Definition, &def); err != nil || def.ClientReport == nil {
		return def, apierror.Validation("the prospect needs the original client report definition")
	}
	def.ClientReport.Period, def.ClientReport.Month = "assessment", ""
	def.ClientReport.Assessment = &reporting.ClientReportAssessment{From: engagement.StartsAt.Format(time.RFC3339Nano),
		To: engagement.EndsAt.Format(time.RFC3339Nano), Preparer: engagement.Preparer}
	if err := cleanDashboardDefinition(&def); err != nil {
		return dashboardDefinition{}, err
	}
	return def, nil
}
