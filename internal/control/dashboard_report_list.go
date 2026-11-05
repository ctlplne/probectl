// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func artifactMetadataView(item store.ReportArtifactMetadata) reportArtifactView {
	out := artifactView(item.ReportArtifact)
	out.BodyBytes, out.BodySHA256 = item.BodyBytes, item.BodySHA256
	return out
}

func (s *Server) listCurrentReportArtifactMetadata(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return apierror.Unavailable("report metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID)), budget.ExecutionLimit)
	defer cancel()
	if err := s.currentReportTenant(ctx, actor.TenantID); err != nil {
		return err
	}
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return tagQueryResponseError(w, tagQueryAdmissionError(err))
		}
		defer release()
	}
	views := make([]reportArtifactView, 0)
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		headers, err := (store.DashboardReports{}).ListArtifactHeaders(ctx, sc, dashboardActorID(r))
		if err != nil {
			return err
		}
		for _, header := range headers {
			if err := ctx.Err(); err != nil {
				return err
			}
			if staticReportMetadata(&header) {
				views = append(views, artifactMetadataView(header))
				continue
			}
			// An unconfigured source lane supplies no current access proof.
			if s.fairnessGate == nil {
				continue
			}
			item, err := s.currentReportArtifactMetadata(ctx, sc, actor, header.ID, dashboardActorID(r))
			if err != nil {
				return err
			}
			if item != nil {
				views = append(views, artifactMetadataView(*item))
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && r.Context().Err() == nil {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("report metadata validation budget exhausted; retry shortly")
		}
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
	return nil
}

// A read savepoint lets an unverifiable source remain hidden without leaving
// this consistent tenant snapshot in an aborted state for subsequent items.
func (s *Server) currentReportArtifactMetadata(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, id, user string) (*store.ReportArtifactMetadata, error) {
	if _, err := sc.Q.Exec(ctx, `SAVEPOINT report_metadata_access`); err != nil {
		return nil, err
	}
	item, accessErr := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, id, user)
	if accessErr == nil && !staticReportMetadata(item) {
		var capture *reportFlowCapture
		capture, accessErr = parseReportSourceRequirements(ctx, item.SourceCapture)
		if accessErr == nil {
			accessErr = s.revalidateReportFlowCaptureScope(ctx, sc, actor, capture)
		}
	}
	if accessErr != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := sc.Q.Exec(ctx, `ROLLBACK TO SAVEPOINT report_metadata_access`); err != nil {
			return nil, err
		}
		_ = s.reportArtifactSourceAccessError(sc.Tenant.String(), id, accessErr)
		item = nil
	}
	if _, err := sc.Q.Exec(ctx, `RELEASE SAVEPOINT report_metadata_access`); err != nil {
		return nil, err
	}
	return item, nil
}
