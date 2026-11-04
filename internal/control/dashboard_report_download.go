// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) downloadDashboardReportArtifact(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID))
	if err := s.currentReportTenant(ctx, actor.TenantID); err != nil {
		return err
	}
	var metadata *store.ReportArtifactMetadata
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		metadata, err = (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, r.PathValue("id"), dashboardActorID(r))
		return err
	}); err != nil {
		return err
	}
	capture, err := s.authorizeStoredReportReader(ctx, actor, metadata)
	if err != nil {
		return reportArtifactReaderError(err)
	}
	if capture != nil {
		if s.fairnessGate == nil {
			return apierror.Unavailable("report body admission is unavailable")
		}
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return tagQueryResponseError(w, tagQueryAdmissionError(err))
		}
		defer release()
	}
	verified, stage, err := s.stageStoredReport(ctx, metadata.ID, dashboardActorID(r))
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }()
	if !sameReportArtifactMetadata(metadata, verified) {
		return apierror.Conflict("report artifact changed during verification; retry")
	}
	if err := s.currentReportTenant(ctx, actor.TenantID); err != nil {
		return err
	}
	if err := s.auditVerifiedReportDownload(r, actor, verified, capture); err != nil {
		return reportArtifactReaderError(err)
	}
	return serveVerifiedReportBody(ctx, w, verified, stage)
}

func (s *Server) currentReportTenant(ctx context.Context, tenant string) error {
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, tenant)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("current report tenant is inactive")
	}
	return nil
}

func (s *Server) authorizeStoredReportReader(ctx context.Context, actor *auth.Principal, metadata *store.ReportArtifactMetadata) (*reportFlowCapture, error) {
	if metadata.BodyStorage == "inline" && len(metadata.SourceCapture) == 0 {
		return nil, nil
	}
	if metadata.BodyStorage != "chunks" {
		return nil, apierror.Internal("stored report representation is invalid")
	}
	capture, err := parseReportSourceRequirements(ctx, metadata.SourceCapture)
	if err != nil {
		return nil, apierror.Internal("stored report source requirements are invalid").Wrap(err)
	}
	if err := s.revalidateReportFlowCapture(ctx, actor, capture); err != nil {
		return nil, err
	}
	return capture, nil
}

func (s *Server) stageStoredReport(ctx context.Context, id, user string) (*store.ReportArtifactMetadata, *reporting.BodyStage, error) {
	var metadata *store.ReportArtifactMetadata
	var stage *reporting.BodyStage
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		metadata, stage, err = (store.DashboardReports{}).StageArtifactBody(ctx, sc, id, user, reporting.DefaultBodyStageLimits())
		return err
	})
	if err != nil {
		if stage != nil {
			_ = stage.Close()
		}
		if errors.Is(err, store.ErrReportArtifactIntegrity) {
			return nil, nil, apierror.Internal("stored report body failed integrity verification").Wrap(err)
		}
		return nil, nil, err
	}
	return metadata, stage, nil
}

func sameReportArtifactMetadata(left, right *store.ReportArtifactMetadata) bool {
	return left != nil && right != nil && left.ID == right.ID && left.TenantID == right.TenantID &&
		left.DashboardID == right.DashboardID && left.BodyStorage == right.BodyStorage && left.BodyBytes == right.BodyBytes &&
		left.Format == right.Format && left.MediaType == right.MediaType && left.Filename == right.Filename &&
		(left.BodyStorage == "inline" && (left.BodySHA256 == "" || right.BodySHA256 == "") ||
			len(left.BodySHA256) == 64 && left.BodySHA256 == right.BodySHA256) &&
		bytes.Equal(left.SourceCapture, right.SourceCapture)
}

func (s *Server) auditVerifiedReportDownload(r *http.Request, actor *auth.Principal, verified *store.ReportArtifactMetadata, capture *reportFlowCapture) error {
	return s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		current, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, verified.ID, dashboardActorID(r))
		if err != nil {
			return err
		}
		if !sameReportArtifactMetadata(verified, current) {
			return apierror.Conflict("report artifact changed during verification; retry")
		}
		if capture != nil {
			if err := s.revalidateReportFlowCaptureScope(ctx, sc, actor, capture); err != nil {
				return err
			}
		}
		return s.recordAudit(ctx, sc, r, "dashboard.report_download", verified.ID, map[string]any{
			"dashboard_id": verified.DashboardID, "format": verified.Format,
			"body_bytes": verified.BodyBytes, "body_sha256": verified.BodySHA256,
		})
	})
}

func reportArtifactReaderError(err error) error {
	if failure, ok := apierror.As(err); ok && (failure.Kind == apierror.KindForbidden || failure.Kind == apierror.KindNotFound) {
		return apierror.NotFound("dashboard report artifact not found")
	}
	return err
}

func serveVerifiedReportBody(ctx context.Context, w http.ResponseWriter, metadata *store.ReportArtifactMetadata, stage *reporting.BodyStage) error {
	reader, err := stage.Open(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	w.Header().Set("Content-Type", metadata.MediaType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", metadata.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(metadata.BodyBytes, 10))
	w.Header().Set("ETag", strconv.Quote("sha256:"+metadata.BodySHA256))
	w.Header().Set("X-Report-SHA256", metadata.BodySHA256)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	buffer := make([]byte, reporting.BodyChunkBytes)
	defer clear(buffer)
	_, err = io.CopyBuffer(w, reader, buffer)
	return err
}
