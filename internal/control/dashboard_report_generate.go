// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func cleanDashboardFlowSources(d *dashboardDefinition) error {
	if len(d.FlowSources) == 0 {
		return nil
	}
	if !d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.IsZero() || len(d.Metrics) != 0 {
		return apierror.Validation("source-backed dashboards derive bounds and values from their saved sources; omit absolute bounds and metrics")
	}
	if len(d.FlowSources) > maxDashboardManifestBytes/64 {
		return apierror.Validation("saved source configuration exceeds the dashboard document budget")
	}
	seen := make(map[string]bool, len(d.FlowSources))
	for _, source := range d.FlowSources {
		if !reportRequirementUUID(source.ID) || seen[source.ID] {
			return apierror.Validation("report flow_sources require distinct canonical saved-query ids")
		}
		if _, err := flow.QueryViewVersion(source.Version); err != nil {
			return apierror.Validation("report flow_sources require exact saved-query versions")
		}
		seen[source.ID] = true
	}
	return nil
}

// The existing operation budget covers source capture, rendering and final
// publication together. Fairness admission remains owned by capture until the
// sealed stage has been published or discarded; no transaction spans rendering.
func (s *Server) generateSourceDashboardReport(r *http.Request, req reportGenerateRequest, view *store.DashboardView, definition dashboardDefinition, tenantName string, tenant tenancy.ID) (*store.ReportArtifactMetadata, error) {
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("report source cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenant), budget.ExecutionLimit)
	defer cancel()
	actor := auth.PrincipalFrom(r.Context())
	capture, err := s.captureConfiguredReportSources(ctx, actor, definition, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer capture.Close()
	document, err := sourceReportDocument(view, definition, tenantName, auditActor(r), time.Now().UTC(), capture)
	if err != nil {
		return nil, err
	}
	requirements, err := marshalReportSourceRequirements(ctx, capture, budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	stage, mediaType, err := stageSourceDashboardReport(ctx, req.Format, document, budget, s.reportOutputPolicy())
	if err != nil {
		return nil, err
	}
	defer func() { _ = stage.Close() }()
	if err := revalidateMonthlyReportOriginals(ctx, capture); err != nil {
		return nil, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return nil, err
	}
	var artifact *store.ReportArtifactMetadata
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant.String()); err != nil {
			return err
		}
		current, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, view.ID, actor.UserID)
		if err != nil {
			return err
		}
		if !dashboardReportViewMatches(view, current) {
			return apierror.Conflict("dashboard changed while its sources were captured; refresh its definition")
		}
		if err := s.validateReportSourcePublication(ctx, sc, actor, capture); err != nil {
			return err
		}
		artifact, err = (store.DashboardReports{}).CreateChunkedArtifact(ctx, sc, sourceReportArtifactInput(id, nil, view, req.Format, mediaType, document), stage, requirements)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r.WithContext(ctx), "dashboard.report_export", id, map[string]any{
			"dashboard_id": view.ID, "format": req.Format, "destination_id": reportInboxDestination,
			"redaction_state": document.RedactionState, "body_bytes": artifact.BodyBytes, "body_sha256": artifact.BodySHA256,
			"source_count": reportCaptureSourceCount(capture),
		})
	})
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

func sourceReportDocument(view *store.DashboardView, definition dashboardDefinition, tenantName, generator string, at time.Time, capture *reportFlowCapture) (reporting.Document, error) {
	if view == nil || capture == nil || view.TenantID != capture.TenantID || len(capture.Inputs) == 0 && capture.Monthly == nil || len(capture.Tables) == 0 {
		return reporting.Document{}, apierror.Forbidden("report captured source scope is unavailable")
	}
	if capture.Monthly != nil {
		provenance := append(append([]string{}, definition.Provenance...), "Monthly original inputs sha256:"+capture.Monthly.InputsDigest)
		period, err := reporting.ResolveClientReportPeriod(context.Background(), *definition.ClientReport, at)
		if capture.monthlyCapture != nil {
			period = capture.monthlyCapture.Period
			err = nil
		}
		if err != nil {
			return reporting.Document{}, err
		}
		provenance = append(provenance, "Calendar: "+period.Timezone+"; period: "+period.Kind+"; month: "+period.Month)
		limitations := append([]string{}, definition.CoverageLimitations...)
		if period.Partial {
			limitations = append(limitations, "Month to date is partial through "+period.To.Format(time.RFC3339Nano)+"; never a complete calendar month.")
		}
		limitations = append(limitations, "Monthly client pack preview; retained observations do not prove complete scheduled coverage.")

		return reporting.Document{Title: view.Name, Preset: view.Preset, TenantName: tenantName, TenantScope: view.TenantID, AbsoluteFrom: capture.Monthly.From, AbsoluteTo: capture.Monthly.To, GeneratedAt: at, GeneratedBy: generator, Provenance: provenance, RedactionState: definition.RedactionState, CoverageLimitations: limitations, Tables: capture.Tables}, nil
	}
	from, to := capture.Inputs[0].From, capture.Inputs[0].To
	for _, input := range capture.Inputs {
		if input.From.Before(from) {
			from = input.From
		}
		if input.To.After(to) {
			to = input.To
		}
	}
	return reporting.Document{Title: view.Name, Preset: view.Preset, TenantName: tenantName, TenantScope: view.TenantID,
		AbsoluteFrom: from, AbsoluteTo: to, GeneratedAt: at, GeneratedBy: generator, Provenance: definition.Provenance,
		RedactionState: definition.RedactionState, CoverageLimitations: definition.CoverageLimitations, Tables: capture.Tables}, nil
}

func stageSourceDashboardReport(ctx context.Context, format string, doc reporting.Document, budget flowstore.ExplorerBudget, policy reporting.OutputPolicy) (*reporting.BodyStage, string, error) {
	if err := budget.Validate(); err != nil {
		return nil, "", err
	}
	limits, err := reportBodyStageLimits(policy, budget)
	if err != nil {
		return nil, "", err
	}
	mediaType := "application/pdf"
	if format == "csv" {
		mediaType = "text/csv"
	} else if format != "pdf" {
		return nil, "", apierror.Validation("report format must be csv or pdf")
	}
	stage, _, err := reporting.StageBody(ctx, doc.TenantScope, limits, func(target io.Writer) error {
		if format == "csv" {
			renderLimits := reporting.DefaultCSVLimits()
			renderLimits.TableRows = policy.CSVRows * 2
			renderLimits.Bytes, renderLimits.MemoryBytes = limits.Bytes, budget.MemoryBytes/4
			_, err := reporting.WriteCSV(ctx, target, doc, renderLimits)
			return err
		}
		renderLimits := reporting.DefaultPDFLimits()
		renderLimits.TableRows = policy.PDFRows * 2
		renderLimits.Bytes, renderLimits.MemoryBytes = limits.Bytes, budget.MemoryBytes/4
		_, err := reporting.WritePDF(ctx, target, doc, renderLimits)
		return err
	})
	return stage, mediaType, err
}

func sourceReportArtifactInput(id string, schedule *string, view *store.DashboardView, format, mediaType string, doc reporting.Document) store.ReportArtifactInput {
	return store.ReportArtifactInput{ID: id, DashboardID: view.ID, ScheduleID: schedule, Format: format, MediaType: mediaType,
		Filename: reportFilename(view.Name, format, doc.GeneratedAt), GeneratedBy: doc.GeneratedBy,
		AbsoluteFrom: doc.AbsoluteFrom, AbsoluteTo: doc.AbsoluteTo, Provenance: doc.Provenance,
		RedactionState: doc.RedactionState, CoverageLimitations: doc.CoverageLimitations}
}

// This publication-only check runs under the canonical audit lock. Source
// mutation commits require that same lock, so ordinary metadata reads give a
// current committed linearization point without inverse source-row locks.
func (s *Server) validateReportSourcePublication(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, capture *reportFlowCapture) error {
	if capture == nil {
		return apierror.Forbidden("report source capture is unavailable")
	}
	if capture.Monthly != nil {
		return s.revalidateClientReportRequirementsScope(ctx, sc, actor, capture.TenantID, capture.Monthly)
	}
	if err := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, capture.SourceGeneration); err != nil {
		return apierror.Conflict("report sources were invalidated during generation; retry after lifecycle completion").Wrap(err)
	}
	if err := s.revalidateReportFlowCaptureScope(ctx, sc, actor, capture); err != nil {
		return err
	}
	access, ok := s.flowQueryViews.(reportScopedSourceAccess)
	if !ok {
		return apierror.Unavailable("report publication source metadata is unavailable")
	}
	seen := map[string]bool{}
	var tagRevision string
	for _, input := range capture.Inputs {
		if seen[input.ID] {
			continue
		}
		seen[input.ID] = true
		current, err := access.GetQueryViewAccessInScope(ctx, sc, actor.UserID, input.ID)
		if err != nil {
			return s.mapFlowViewStoreError(ctx, actor, err)
		}
		if current.Version != input.Version {
			return apierror.Conflict("saved report source changed during generation")
		}
		if input.TagRevision != "" {
			if tagRevision == "" {
				var revision int64
				if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1)`, sc.Tenant.String()).Scan(&revision); err != nil {
					return err
				}
				tagRevision = strconv.FormatInt(revision, 10)
			}
			if tagRevision != input.TagRevision {
				return apierror.Conflict("report source metadata changed during generation")
			}
		}
	}
	ids := make([]string, 0, len(capture.FilterVersions))
	for id := range capture.FilterVersions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var version int64
		if err := sc.Q.QueryRow(ctx, `SELECT version FROM flow_query_filters WHERE tenant_id=$1::uuid AND id=$2::uuid`, sc.Tenant.String(), id).Scan(&version); err != nil {
			return err
		}
		if version != capture.FilterVersions[id] {
			return apierror.Conflict("saved report source filter changed during generation")
		}
	}
	return ctx.Err()
}

func reportGenerationError(err error) error {
	switch {
	case errors.Is(err, store.ErrClientReportBudget), errors.Is(err, reporting.ErrBodyStageLimit), errors.Is(err, reporting.ErrCSVLimit), errors.Is(err, reporting.ErrPDFLimit), errors.Is(err, context.DeadlineExceeded):
		return apierror.RateLimited("complete report exceeds the current output or execution budget; increase the corresponding configured admission and retry").Wrap(err)
	case errors.Is(err, flowsnapshot.ErrInvalidating):
		return apierror.Conflict("report source lifecycle transition is incomplete; retry after completion").Wrap(err)
	case errors.Is(err, fairness.ErrQueryConcurrency), errors.Is(err, fairness.ErrQueryBudget):
		return tagQueryAdmissionError(err)
	default:
		return err
	}
}

func reportCaptureSourceCount(capture *reportFlowCapture) int {
	if capture.Monthly != nil {
		return len(capture.Monthly.Bindings)
	}
	seen := map[string]bool{}
	for _, input := range capture.Inputs {
		seen[input.ID] = true
	}
	return len(seen)
}
