// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func (s *DashboardReportSupervisor) eraseDueProspect(ctx context.Context, tenant string, resume bool) error {
	server := s.sourceServer
	if server == nil {
		return nil
	}
	engine, ok := server.tenantLife.(*tenantlife.Engine)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(tenant)), eraseWriteBudget)
	defer cancel()
	if resume {
		att, attempted, err := engine.ResumeProspectErasure(ctx, tenant)
		if err != nil || !attempted {
			return err
		}
		return requireCompleteProspectErasure(att)
	}

	engagement, evidence, err := s.dueProspectErasureEvidence(ctx)
	if err != nil || evidence == nil {
		return err
	}
	if server.fairnessGate == nil {
		return apierror.Unavailable("prospect verification admission is unavailable")
	}
	release, err := server.fairnessGate.BeginQuery(ctx, tenant)
	if err != nil {
		return err
	}
	defer release()
	metadata, capture, err := server.verifyProspectErasureReport(ctx, engagement, *evidence)
	if err != nil {
		return err
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(server)
	att, err := engine.EraseProspect(ctx, tenant, engagement, *evidence, dashboardReportSchedulerActor,
		func(ctx context.Context, sc tenancy.Scope) error {
			return server.revalidateProspectErasure(ctx, sc, engagement, metadata, capture)
		})
	if err != nil {
		return err
	}
	return requireCompleteProspectErasure(att)
}

func (s *DashboardReportSupervisor) dueProspectErasureEvidence(ctx context.Context) (store.ProspectEngagement, *store.ProspectErasureEvidence, error) {
	var engagement store.ProspectEngagement
	var evidence *store.ProspectErasureEvidence
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		engagement, err = (store.ProspectEngagements{}).Get(ctx, sc)
		if domain, ok := apierror.As(err); ok && domain.Kind == apierror.KindNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		evidence, err = (store.ProspectEngagements{}).ErasureEvidence(ctx, sc, engagement, dashboardReportSchedulerActor)
		return err
	})
	return engagement, evidence, err
}

func (s *Server) verifyProspectErasureReport(ctx context.Context, engagement store.ProspectEngagement, evidence store.ProspectErasureEvidence) (*store.ReportArtifactMetadata, *reportFlowCapture, error) {
	tenant, _ := tenancy.FromContext(ctx)
	current, err := loadCurrentUserAuthority(ctx, s.pool, tenant.String(), engagement.OwnerID)
	if err != nil {
		return nil, nil, err
	}
	ctx, actor, err := s.prospectErasureSourceAuthority(ctx, current)
	if err != nil {
		return nil, nil, err
	}
	metadata, stage, err := s.stageStoredReport(ctx, evidence.ArtifactID, engagement.OwnerID)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = stage.Close() }()
	if metadata.BodySHA256 != evidence.BodySHA256 || metadata.BodyBytes != evidence.BodyBytes {
		return nil, nil, apierror.Conflict("the verified assessment differs from the delivered report")
	}
	capture, err := s.readStoredReportSourceRequirements(ctx, metadata)
	if err != nil {
		return nil, nil, err
	}
	if capture == nil || capture.Monthly == nil {
		return nil, nil, apierror.Conflict("the original prospect report evidence is unavailable")
	}
	if err := s.revalidateReportFlowCapture(ctx, actor, capture); err != nil {
		return nil, nil, err
	}
	return metadata, capture, nil
}

func (s *Server) revalidateProspectErasure(ctx context.Context, sc tenancy.Scope, engagement store.ProspectEngagement,
	verified *store.ReportArtifactMetadata, capture *reportFlowCapture) error {
	if err := s.validateReportDestination(sc.Tenant.String(), engagement.DestinationID); err != nil {
		return err
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, engagement.OwnerID)
	if err != nil {
		return err
	}
	ctx, actor, err := s.prospectErasureSourceAuthority(ctx, current)
	if err != nil {
		return err
	}
	view, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, engagement.AssessmentViewID, engagement.OwnerID)
	if err != nil {
		return err
	}
	if view.OwnerID != engagement.OwnerID || !view.UpdatedAt.Equal(engagement.AssessmentAt) {
		return apierror.Conflict("the original prospect report definition changed")
	}
	latest, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, verified.ID, engagement.OwnerID, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/4)
	if err != nil {
		return err
	}
	if !sameReportArtifactMetadata(verified, latest) {
		return apierror.Conflict("the verified assessment changed before erasure")
	}
	return s.revalidateReportFlowCaptureScope(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture)
}

func (s *Server) prospectErasureSourceAuthority(ctx context.Context, current *currentUserAuthority) (context.Context, *auth.Principal, error) {
	checked, actor, err := current.requestContext(ctx, current.principal)
	if err != nil {
		return nil, nil, err
	}
	resource := map[string]string{auth.ResourceTenantKey: actor.TenantID}
	for _, permission := range []string{permLifecycleErase, permLifecycleExp, "metrics.read"} {
		if err := s.authorize(checked, actor, permission, auth.RBACGlobal, resource); err != nil {
			return nil, nil, err
		}
	}
	return current.backgroundContext(ctx, reportBackgroundSourcePermissions())
}

func requireCompleteProspectErasure(att tenantlife.Attestation) error {
	if !att.Complete {
		return errors.New("prospect erasure is waiting for verified deletion across the tenant's stores")
	}
	return nil
}
