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
	"net/http"
	"net/url"

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
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return apierror.Validation("report inbox query is invalid")
	}
	limit, position, err := parseReportInboxPage(query, actor.TenantID, dashboardActorID(r), budget.MemoryBytes)
	if errors.Is(err, store.ErrReportMetadataBudget) {
		w.Header().Set("Retry-After", "1")
		return apierror.RateLimited("report metadata cursor budget exhausted")
	}
	if err != nil {
		return err
	}
	views := make([]reportArtifactView, 0)
	nextCursor := ""
	remaining := budget.MemoryBytes
	responseBytes := int64(32)
	var lastVisible store.ReportArtifactPosition
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		for {
			headers, charged, err := (store.DashboardReports{}).ListArtifactHeaderBatch(ctx, sc, dashboardActorID(r), position, remaining)
			if err != nil {
				return err
			}
			remaining -= charged
			for _, header := range headers {
				if err := ctx.Err(); err != nil {
					return err
				}
				item := &header
				if !staticReportMetadata(item) {
					// An unconfigured source lane supplies no current access proof.
					if s.fairnessGate == nil {
						continue
					}
					item, err = s.currentReportArtifactMetadata(ctx, sc, actor, header.ID, dashboardActorID(r))
					if err != nil {
						return err
					}
					if item == nil {
						continue
					}
				}
				if len(views) == limit {
					// The cursor names only metadata already returned to this caller.
					nextCursor, err = encodeReportInboxCursor(actor.TenantID, dashboardActorID(r), lastVisible)
					return err
				}
				view := artifactMetadataView(*item)
				raw, err := json.Marshal(view)
				if err != nil {
					return err
				}
				if int64(len(raw))+1 > budget.ResponseBytes-responseBytes {
					return store.ErrReportMetadataBudget
				}
				responseBytes += int64(len(raw)) + 1
				views = append(views, view)
				lastVisible = store.ReportArtifactPosition{GeneratedAt: header.GeneratedAt, ID: header.ID}
			}
			if len(headers) < store.ReportArtifactHeaderBatchRows {
				return nil
			}
			last := headers[len(headers)-1]
			position = &store.ReportArtifactPosition{GeneratedAt: last.GeneratedAt, ID: last.ID}
		}
	})
	if err != nil {
		if (errors.Is(err, context.DeadlineExceeded) && r.Context().Err() == nil) || errors.Is(err, store.ErrReportMetadataBudget) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("report metadata validation budget exhausted; retry shortly")
		}
		return err
	}
	page := struct {
		Items      []reportArtifactView `json:"items"`
		NextCursor string               `json:"next_cursor,omitempty"`
	}{views, nextCursor}
	raw, err := json.Marshal(page)
	if err != nil {
		return err
	}
	if int64(len(raw)) > budget.ResponseBytes {
		w.Header().Set("Retry-After", "1")
		return apierror.RateLimited("report metadata response budget exhausted; retry with a smaller page")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

// A read savepoint lets an unverifiable source remain hidden without leaving
// this consistent tenant snapshot in an aborted state for subsequent items.
func (s *Server) currentReportArtifactMetadata(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, id, user string) (*store.ReportArtifactMetadata, error) {
	if _, err := sc.Q.Exec(ctx, `SAVEPOINT report_metadata_access`); err != nil {
		return nil, err
	}
	item, accessErr := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, id, user, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/4)
	if accessErr == nil && !staticReportMetadata(item) {
		var capture *reportFlowCapture
		capture, accessErr = parseReportSourceRequirements(ctx, item.SourceCapture, flowstore.ExplorerQueryBudget(s.flowStore).MemoryBytes/4)
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
