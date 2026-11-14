// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	reportInboxDestination    = "tenant-report-inbox"
	dashboardManifestVersion  = "probectl.io/dashboard/v1"
	dashboardManifestKind     = "Dashboard"
	maxDashboardManifestBytes = 64 << 10
	maxReportMetrics          = 100
	maxReportDisclosure       = 20
	// Compatibility-format threshold only; larger complete documents use chunks.
	maxInlineReportBytes = 2 << 20
)

type dashboardDefinition = reporting.DashboardDefinition

type dashboardCreateRequest = reporting.DashboardCreateInput

// dashboardManifest is the stable, portable representation of a native saved
// dashboard. Identity and storage fields are absent by construction: the
// importing server derives tenant, owner, id, and timestamps.
type dashboardManifest = reporting.DashboardManifest

type dashboardManifestMetadata = reporting.DashboardManifestMetadata

type dashboardManifestSpec = reporting.DashboardManifestSpec

type dashboardManifestDefinition = reporting.DashboardManifestDefinition

type dashboardManifestMetric = reporting.DashboardManifestMetric

type dashboardManifestFlowSource = reporting.DashboardManifestFlowSource

type dashboardManifestImportRequest = reporting.DashboardManifestImportInput

type dashboardManifestPreview = reporting.DashboardManifestPreview

type dashboardManifestImportResponse struct {
	Status    string                   `json:"status"`
	Manifest  dashboardManifest        `json:"manifest"`
	Preview   dashboardManifestPreview `json:"preview"`
	Dashboard *store.DashboardView     `json:"dashboard,omitempty"`
}

type reportScheduleCreateRequest = reporting.ReportScheduleInput

type reportGenerateRequest = reporting.ReportGenerateInput

type reportDestination struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Outbound bool   `json:"outbound"`
	Ready    bool   `json:"ready"`
}

type reportArtifactView struct {
	ID                  string          `json:"id"`
	DashboardID         string          `json:"dashboard_id"`
	ScheduleID          *string         `json:"schedule_id,omitempty"`
	Format              string          `json:"format"`
	MediaType           string          `json:"media_type"`
	Filename            string          `json:"filename"`
	GeneratedBy         string          `json:"generated_by"`
	GeneratedAt         time.Time       `json:"generated_at"`
	AbsoluteFrom        time.Time       `json:"absolute_from"`
	AbsoluteTo          time.Time       `json:"absolute_to"`
	Provenance          json.RawMessage `json:"provenance"`
	RedactionState      string          `json:"redaction_state"`
	CoverageLimitations json.RawMessage `json:"coverage_limitations"`
	DownloadURL         string          `json:"download_url"`
	BodyBytes           int64           `json:"body_bytes,omitempty"`
	BodySHA256          string          `json:"body_sha256,omitempty"`
}

func dashboardActorID(r *http.Request) string {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return ""
	}
	if strings.TrimSpace(p.UserID) != "" {
		return p.UserID
	}
	return p.Email
}

func cleanDashboardCreate(req dashboardCreateRequest) (dashboardCreateRequest, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Preset = strings.ToLower(strings.TrimSpace(req.Preset))
	if req.Name == "" || len(req.Name) > 120 {
		return req, apierror.Validation("dashboard name must be between 1 and 120 characters")
	}
	if req.Preset != "operator" && req.Preset != "executive" {
		return req, apierror.Validation("preset must be operator or executive")
	}
	if err := cleanDashboardDefinition(&req.Definition); err != nil {
		return req, err
	}
	return req, nil
}

func cleanDashboardDefinition(d *dashboardDefinition) error {
	if err := cleanClientReportDefinition(d); err != nil {
		return err
	}
	if err := cleanDashboardFlowSources(d); err != nil {
		return err
	}
	if d.ClientReport == nil && len(d.FlowSources) == 0 && (d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.After(d.AbsoluteFrom)) {
		return apierror.Validation("definition requires an absolute_from earlier than absolute_to")
	}
	if d.ClientReport == nil && len(d.FlowSources) == 0 && d.AbsoluteTo.Sub(d.AbsoluteFrom) > 366*24*time.Hour {
		return apierror.Validation("dashboard time range may not exceed 366 days")
	}
	d.RedactionState = strings.TrimSpace(d.RedactionState)
	if d.RedactionState == "" || len(d.RedactionState) > 120 {
		return apierror.Validation("redaction_state must be between 1 and 120 characters")
	}
	if err := cleanDisclosure(&d.Provenance, "provenance"); err != nil {
		return err
	}
	if err := cleanDisclosure(&d.CoverageLimitations, "coverage_limitations"); err != nil {
		return err
	}
	if len(d.Metrics) > maxReportMetrics {
		return apierror.Validation("dashboard definition may contain at most 100 exact metrics")
	}
	cleanMetrics := make(map[string]string, len(d.Metrics))
	for key, value := range d.Metrics {
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || len(key) > 80 || len(value) > 240 {
			return apierror.Validation("metric names must be 1-80 characters and values at most 240 characters")
		}
		cleanMetrics[key] = value
	}
	d.Metrics = cleanMetrics
	return nil
}

func cleanDisclosure(values *[]string, field string) error {
	if len(*values) == 0 || len(*values) > maxReportDisclosure {
		return apierror.Validation(field + " must contain between 1 and 20 entries")
	}
	clean := make([]string, 0, len(*values))
	for _, value := range *values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 240 {
			return apierror.Validation(field + " entries must be between 1 and 240 characters")
		}
		clean = append(clean, value)
	}
	*values = clean
	return nil
}

func dashboardManifestToCreate(manifest dashboardManifest) (dashboardCreateRequest, error) {
	return dashboardManifestToCreateBound(manifest, nil)
}

func dashboardManifestToCreateBound(manifest dashboardManifest, bindings map[string]reportFlowSourceRef) (dashboardCreateRequest, error) {
	if manifest.APIVersion != dashboardManifestVersion {
		return dashboardCreateRequest{}, apierror.Validation(
			"unsupported dashboard manifest api_version; expected " + dashboardManifestVersion,
		)
	}
	if manifest.Kind != dashboardManifestKind {
		return dashboardCreateRequest{}, apierror.Validation("dashboard manifest kind must be Dashboard")
	}
	if len(manifest.Spec.Definition.Metrics) > maxReportMetrics {
		return dashboardCreateRequest{}, apierror.Validation("dashboard definition may contain at most 100 exact metrics")
	}
	refs, err := dashboardManifestSourceRefs(manifest.Spec.Definition.FlowSources, bindings)
	if err != nil {
		return dashboardCreateRequest{}, err
	}
	metrics := make(map[string]string, len(manifest.Spec.Definition.Metrics))
	for _, metric := range manifest.Spec.Definition.Metrics {
		name := strings.TrimSpace(metric.Name)
		if _, exists := metrics[name]; exists {
			return dashboardCreateRequest{}, apierror.Validation("dashboard manifest metric names must be unique")
		}
		metrics[name] = metric.Value
	}
	return cleanDashboardCreate(dashboardCreateRequest{
		Name:   manifest.Metadata.Name,
		Preset: manifest.Spec.Preset,
		Shared: manifest.Spec.Shared,
		Definition: dashboardDefinition{
			ClientReport: manifest.Spec.Definition.ClientReport, FlowSources: refs,
			AbsoluteFrom:        manifest.Spec.Definition.AbsoluteFrom,
			AbsoluteTo:          manifest.Spec.Definition.AbsoluteTo,
			Provenance:          manifest.Spec.Definition.Provenance,
			RedactionState:      manifest.Spec.Definition.RedactionState,
			CoverageLimitations: manifest.Spec.Definition.CoverageLimitations,
			Metrics:             metrics,
		},
	})
}

func dashboardCreateToManifest(req dashboardCreateRequest) dashboardManifest {
	names := make([]string, 0, len(req.Definition.Metrics))
	for name := range req.Definition.Metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	metrics := make([]dashboardManifestMetric, 0, len(names))
	for _, name := range names {
		metrics = append(metrics, dashboardManifestMetric{Name: name, Value: req.Definition.Metrics[name]})
	}
	return dashboardManifest{
		APIVersion: dashboardManifestVersion,
		Kind:       dashboardManifestKind,
		Metadata:   dashboardManifestMetadata{Name: req.Name},
		Spec: dashboardManifestSpec{
			Preset: req.Preset,
			Shared: req.Shared,
			Definition: dashboardManifestDefinition{
				ClientReport: req.Definition.ClientReport, FlowSources: dashboardManifestSourceSlots(req.Definition.FlowSources),
				AbsoluteFrom:        req.Definition.AbsoluteFrom,
				AbsoluteTo:          req.Definition.AbsoluteTo,
				Provenance:          req.Definition.Provenance,
				RedactionState:      req.Definition.RedactionState,
				CoverageLimitations: req.Definition.CoverageLimitations,
				Metrics:             metrics,
			},
		},
	}
}

func sanitizeDashboardCreate(req dashboardCreateRequest, identities ...string) (dashboardCreateRequest, error) {
	policy := govern.DefaultPIIPolicy()
	sanitizeText := func(value string) string {
		for _, identity := range identities {
			if identity != "" {
				value = strings.ReplaceAll(value, identity, "[redacted]")
			}
		}
		return govern.RedactTelemetryText(policy, value)
	}
	req.Name = sanitizeText(req.Name)
	req.Definition.RedactionState = sanitizeText(req.Definition.RedactionState)
	for i := range req.Definition.Provenance {
		req.Definition.Provenance[i] = sanitizeText(req.Definition.Provenance[i])
	}
	for i := range req.Definition.CoverageLimitations {
		req.Definition.CoverageLimitations[i] = sanitizeText(req.Definition.CoverageLimitations[i])
	}
	metrics := make(map[string]string, len(req.Definition.Metrics))
	names := make([]string, 0, len(req.Definition.Metrics))
	for name := range req.Definition.Metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cleanName := sanitizeText(name)
		if _, exists := metrics[cleanName]; exists {
			return req, apierror.Validation("dashboard metric names collide after identity redaction")
		}
		metrics[cleanName] = govern.RedactTelemetryAttribute(policy, cleanName, sanitizeText(req.Definition.Metrics[name]))
	}
	req.Definition.Metrics = metrics
	return cleanDashboardCreate(req)
}

func dashboardManifestPreviewFor(req dashboardCreateRequest) dashboardManifestPreview {
	return dashboardManifestPreview{
		Name:                    req.Name,
		Preset:                  req.Preset,
		Shared:                  req.Shared,
		AbsoluteFrom:            req.Definition.AbsoluteFrom,
		AbsoluteTo:              req.Definition.AbsoluteTo,
		MetricCount:             len(req.Definition.Metrics),
		SourceCount:             len(req.Definition.FlowSources),
		ProvenanceCount:         len(req.Definition.Provenance),
		CoverageLimitationCount: len(req.Definition.CoverageLimitations),
	}
}

func dashboardManifestFromView(view *store.DashboardView) (dashboardManifest, error) {
	var definition dashboardDefinition
	if err := json.Unmarshal(view.Definition, &definition); err != nil {
		return dashboardManifest{}, apierror.Internal("stored dashboard definition is invalid").Wrap(err)
	}
	clean, err := cleanDashboardCreate(dashboardCreateRequest{
		Name: view.Name, Preset: view.Preset, Shared: view.Shared, Definition: definition,
	})
	if err != nil {
		return dashboardManifest{}, apierror.Internal("stored dashboard definition is invalid").Wrap(err)
	}
	identities := []string{view.TenantID, view.OwnerID}
	for _, ref := range clean.Definition.FlowSources {
		identities = append(identities, ref.ID)
	}
	clean, err = sanitizeDashboardCreate(clean, identities...)
	if err != nil {
		return dashboardManifest{}, err
	}
	return dashboardCreateToManifest(clean), nil
}

func (s *Server) handleCreateDashboard(w http.ResponseWriter, r *http.Request) error {
	var req dashboardCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	clean, err := cleanDashboardCreate(req)
	if err != nil {
		return err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return apierror.Internal("could not generate dashboard id").Wrap(err)
	}
	definition, err := json.Marshal(clean.Definition)
	if err != nil {
		return err
	}
	var view *store.DashboardView
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := s.validateDashboardFlowSourceRefs(ctx, sc, auth.PrincipalFrom(r.Context()), clean.Definition.FlowSources); err != nil {
			return tagQueryResponseError(w, err)
		}
		created, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{
			ID: id, OwnerID: dashboardActorID(r), Name: clean.Name, Preset: clean.Preset,
			Shared: clean.Shared, Definition: definition,
		})
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.save", id, map[string]any{
			"preset": clean.Preset, "shared": clean.Shared,
		}); err != nil {
			return err
		}
		view = created
		return nil
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/dashboards/"+id)
	writeJSON(w, http.StatusCreated, view)
	return nil
}

func (s *Server) handleListDashboards(w http.ResponseWriter, r *http.Request) error {
	var items []store.DashboardView
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, err = (store.DashboardReports{}).ListViews(ctx, sc, dashboardActorID(r))
		return err
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
	return nil
}

func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) error {
	var view *store.DashboardView
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		view, err = (store.DashboardReports{}).GetView(ctx, sc, r.PathValue("id"), dashboardActorID(r))
		return err
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, view)
	return nil
}

func (s *Server) handleExportDashboardManifest(w http.ResponseWriter, r *http.Request) error {
	var manifest dashboardManifest
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		view, err := (store.DashboardReports{}).GetView(ctx, sc, r.PathValue("id"), dashboardActorID(r))
		if err != nil {
			return err
		}
		manifest, err = dashboardManifestFromView(view)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "dashboard.manifest_export", view.ID, map[string]any{
			"api_version": dashboardManifestVersion,
			"shared":      view.Shared,
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-dashboard.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, http.StatusOK, manifest)
	return nil
}

func (s *Server) handleImportDashboardManifest(w http.ResponseWriter, r *http.Request) error {
	var body dashboardManifestImportRequest
	if err := decodeJSONLimit(r, maxDashboardManifestBytes, &body); err != nil {
		return err
	}
	clean, err := dashboardManifestToCreateBound(body.Manifest, body.SourceBindings)
	if err != nil {
		return err
	}

	var response dashboardManifestImportResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := s.validateDashboardFlowSourceRefs(ctx, sc, auth.PrincipalFrom(r.Context()), clean.Definition.FlowSources); err != nil {
			return tagQueryResponseError(w, err)
		}
		sanitized, err := sanitizeDashboardCreate(clean, sc.Tenant.String(), dashboardActorID(r))
		if err != nil {
			return err
		}
		response = dashboardManifestImportResponse{
			Status:   "preview",
			Manifest: dashboardCreateToManifest(sanitized),
			Preview:  dashboardManifestPreviewFor(sanitized),
		}
		target := "dashboard-manifest-preview"
		if body.Confirm {
			id, err := crypto.UUIDv4()
			if err != nil {
				return apierror.Internal("could not generate dashboard id").Wrap(err)
			}
			definition, err := json.Marshal(sanitized.Definition)
			if err != nil {
				return err
			}
			created, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{
				ID: id, OwnerID: dashboardActorID(r), Name: sanitized.Name, Preset: sanitized.Preset,
				Shared: sanitized.Shared, Definition: definition,
			})
			if err != nil {
				return err
			}
			response.Status = "created"
			response.Dashboard = created
			target = id
		}
		return s.recordAudit(ctx, sc, r, "dashboard.manifest_import", target, map[string]any{
			"api_version": dashboardManifestVersion,
			"confirmed":   body.Confirm,
			"shared":      sanitized.Shared,
		})
	}); err != nil {
		return err
	}
	status := http.StatusOK
	if body.Confirm {
		status = http.StatusCreated
		w.Header().Set("Location", "/v1/dashboards/"+response.Dashboard.ID)
	}
	writeJSON(w, status, response)
	return nil
}

func cleanSchedule(req reportScheduleCreateRequest) (reportScheduleCreateRequest, error) {
	req.DashboardID = strings.TrimSpace(req.DashboardID)
	req.Name = strings.TrimSpace(req.Name)
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	req.Cadence = strings.ToLower(strings.TrimSpace(req.Cadence))
	req.DestinationID = strings.TrimSpace(req.DestinationID)
	if req.DashboardID == "" || req.Name == "" || len(req.Name) > 120 {
		return req, apierror.Validation("dashboard_id and a 1-120 character schedule name are required")
	}
	if req.Format != "pdf" && req.Format != "csv" {
		return req, apierror.Validation("format must be pdf or csv")
	}
	if req.Cadence != "daily" && req.Cadence != "weekly" && req.Cadence != "monthly" {
		return req, apierror.Validation("cadence must be daily, weekly, or monthly")
	}
	if req.DestinationID != reportInboxDestination {
		return req, apierror.Validation("destination is not configured for tenant report delivery")
	}
	if req.FirstRunAt.IsZero() {
		req.FirstRunAt = time.Now().UTC().Add(24 * time.Hour)
	}
	if req.FirstRunAt.Before(time.Now().UTC().Add(-time.Minute)) {
		return req, apierror.Validation("first_run_at may not be in the past")
	}
	return req, nil
}

func (s *Server) handleCreateReportSchedule(w http.ResponseWriter, r *http.Request) error {
	var req reportScheduleCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	clean, err := cleanSchedule(req)
	if err != nil {
		return err
	}
	if clean.ProviderTriggerAllowed && !s.providerReportTriggers {
		return apierror.NotFound("provider report triggering is unavailable")
	}
	authority, err := s.prepareScheduledReportAuthority(r, clean.DashboardID)
	if err != nil {
		return tagQueryResponseError(w, err)
	}
	defer authority.close()
	if clean.ProviderTriggerAllowed && (authority.capture == nil || authority.capture.Monthly == nil) {
		return apierror.Validation("provider triggering requires a monthly source schedule")
	}
	r = authority.request
	id, err := crypto.UUIDv4()
	if err != nil {
		return apierror.Internal("could not generate report schedule id").Wrap(err)
	}
	var schedule *store.ReportSchedule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := s.validateScheduledReportAuthority(ctx, sc, authority); err != nil {
			return err
		}
		created, err := (store.DashboardReports{}).CreateSchedule(ctx, sc, store.ReportScheduleInput{
			ID: id, DashboardID: clean.DashboardID, OwnerID: dashboardActorID(r), Name: clean.Name,
			Format: clean.Format, Cadence: clean.Cadence, DestinationID: clean.DestinationID,
			NextRunAt: clean.FirstRunAt, ProviderTriggerAllowed: clean.ProviderTriggerAllowed,
		})
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_schedule", id, map[string]any{
			"dashboard_id": clean.DashboardID, "format": clean.Format,
			"cadence": clean.Cadence, "destination_id": clean.DestinationID, "provider_trigger_allowed": clean.ProviderTriggerAllowed,
		}); err != nil {
			return err
		}
		schedule = created
		return nil
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/dashboard-report-schedules/"+id)
	writeJSON(w, http.StatusCreated, schedule)
	return nil
}

func (s *Server) handleUpdateReportSchedule(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Enabled                *bool `json:"enabled"`
		ProviderTriggerAllowed *bool `json:"provider_trigger_allowed"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Enabled == nil && req.ProviderTriggerAllowed == nil {
		return apierror.Validation("enabled or provider_trigger_allowed must be a boolean")
	}
	if req.ProviderTriggerAllowed != nil && *req.ProviderTriggerAllowed && !s.providerReportTriggers {
		return apierror.NotFound("provider report triggering is unavailable")
	}
	var authority *scheduledReportAuthority
	if req.Enabled != nil && *req.Enabled || req.ProviderTriggerAllowed != nil && *req.ProviderTriggerAllowed {
		var current *store.ReportSchedule
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			current, err = (store.DashboardReports{}).GetSchedule(ctx, sc, r.PathValue("id"), dashboardActorID(r))
			return err
		}); err != nil {
			return err
		}
		var err error
		authority, err = s.prepareScheduledReportAuthority(r, current.DashboardID)
		if err != nil {
			return tagQueryResponseError(w, err)
		}
		defer authority.close()
		if req.ProviderTriggerAllowed != nil && *req.ProviderTriggerAllowed && (authority.capture == nil || authority.capture.Monthly == nil) {
			return apierror.Validation("provider triggering requires a monthly source schedule")
		}
		r = authority.request
	}
	var schedule *store.ReportSchedule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if authority != nil {
			if err := s.validateScheduledReportAuthority(ctx, sc, authority); err != nil {
				return err
			}
		}
		var updated *store.ReportSchedule
		var err error
		if req.ProviderTriggerAllowed != nil {
			updated, err = (store.DashboardReports{}).SetScheduleProviderControl(ctx, sc, r.PathValue("id"), dashboardActorID(r), *req.ProviderTriggerAllowed, req.Enabled)
		} else {
			updated, err = (store.DashboardReports{}).SetScheduleEnabled(ctx, sc, r.PathValue("id"), dashboardActorID(r), *req.Enabled)
		}
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_schedule_update", updated.ID, map[string]any{"enabled": updated.Enabled, "provider_trigger_allowed": updated.ProviderTriggerAllowed}); err != nil {
			return err
		}
		schedule = updated
		return nil
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, schedule)
	return nil
}

func (s *Server) handleListReportSchedules(w http.ResponseWriter, r *http.Request) error {
	var items []store.ReportSchedule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, err = (store.DashboardReports{}).ListSchedules(ctx, sc, dashboardActorID(r))
		return err
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"destinations": []reportDestination{{
			ID: reportInboxDestination, Name: "Tenant report inbox", Kind: "local", Outbound: false, Ready: true,
		}},
		"outbound_default":           false,
		"provider_trigger_available": s.providerReportTriggers,
	})
	return nil
}

func (s *Server) handleGenerateDashboardReport(w http.ResponseWriter, r *http.Request) error {
	var req reportGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.DashboardID = strings.TrimSpace(req.DashboardID)
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	if req.DashboardID == "" || (req.Format != "pdf" && req.Format != "csv") {
		return apierror.Validation("dashboard_id and format pdf or csv are required")
	}
	artifact, err := s.generateDashboardReportWithStager(r, req, stageStaticDashboardReport)
	if err != nil {
		return tagQueryResponseError(w, reportGenerationError(err))
	}
	w.Header().Set("Location", "/v1/dashboard-report-artifacts/"+artifact.ID)
	writeJSON(w, http.StatusCreated, artifactView(*artifact))
	return nil
}

type dashboardReportRenderer func(context.Context, string, reporting.Document) ([]byte, string, error)

// Compatibility adapter for embedded callers and the original publication
// hooks. Production generation keeps the sealed stage instead of a body copy.
func renderDashboardReport(ctx context.Context, format string, doc reporting.Document) ([]byte, string, error) {
	profile, err := staticReportOperation(ctx)
	if err != nil {
		return nil, "", err
	}
	// Reserve room for the compatibility byte copy as well as staged buffers.
	profile.output.Bytes = min(profile.output.Bytes, profile.budget.MemoryBytes/4)
	ctx, cancel := profile.context(ctx)
	defer cancel()
	stage, media, err := stageStaticDashboardReport(ctx, format, doc)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = stage.Close() }()
	reader, err := stage.Open(ctx)
	if err != nil {
		return nil, "", err
	}
	content, err := io.ReadAll(reader)
	closed := reader.Close()
	if err != nil {
		return nil, "", err
	}
	if closed != nil {
		return nil, "", closed
	}
	if err := ctx.Err(); err != nil {
		clear(content)
		return nil, "", err
	}
	return content, media, nil
}

func (s *Server) generateDashboardReport(r *http.Request, req reportGenerateRequest, render dashboardReportRenderer) (*store.ReportArtifact, error) {
	if render == nil {
		return nil, apierror.Unavailable("dashboard report renderer is unavailable")
	}
	return s.generateDashboardReportWithStager(r, req, func(ctx context.Context, format string, doc reporting.Document) (*reporting.BodyStage, string, error) {
		return stageLegacyDashboardReport(ctx, format, doc, render)
	})
}

// Rendering may need current source reads. It runs after the capture transaction
// has released its connection; no database transaction is held during that IO.
// A separate short transaction rechecks visibility and the complete definition
// before committing the artifact and audit together.
func (s *Server) generateDashboardReportWithStager(r *http.Request, req reportGenerateRequest, render dashboardReportStager) (*store.ReportArtifact, error) {
	if render == nil {
		return nil, apierror.Unavailable("dashboard report renderer is unavailable")
	}
	var view *store.DashboardView
	var definition dashboardDefinition
	var tenantName string
	var capturedTenant tenancy.ID
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if bound, ok := tenancy.FromContext(r.Context()); ok && bound != sc.Tenant {
			return apierror.Forbidden("dashboard report tenant scope disagrees")
		}
		capturedTenant = sc.Tenant
		var err error
		view, err = (store.DashboardReports{}).GetView(ctx, sc, req.DashboardID, dashboardActorID(r))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(view.Definition, &definition); err != nil {
			return apierror.Internal("stored dashboard definition is invalid").Wrap(err)
		}
		if err := cleanDashboardDefinition(&definition); err != nil {
			return apierror.Internal("stored dashboard definition failed validation").Wrap(err)
		}
		tenantName, err = dashboardTenantName(ctx, sc)
		return err
	}); err != nil {
		return nil, err
	}

	if len(definition.FlowSources) > 0 || definition.ClientReport != nil {
		metadata, err := s.generateSourceDashboardReport(r, req, view, definition, tenantName, capturedTenant)
		if err != nil {
			return nil, err
		}
		return &metadata.ReportArtifact, nil
	}
	now := time.Now().UTC()
	doc := reporting.Document{
		Title: view.Name, Preset: view.Preset, TenantName: tenantName,
		TenantScope: view.TenantID, AbsoluteFrom: definition.AbsoluteFrom,
		AbsoluteTo: definition.AbsoluteTo, GeneratedAt: now, GeneratedBy: auditActor(r),
		Provenance: definition.Provenance, RedactionState: definition.RedactionState,
		CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics,
	}
	profile, err := s.staticReportOperation()
	if err != nil {
		return nil, err
	}
	renderContext, cancel := profile.context(tenancy.WithTenant(r.Context(), capturedTenant))
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(renderContext, capturedTenant.String())
		if err != nil {
			return nil, err
		}
		defer release()
	}
	stage, mediaType, err := render(renderContext, req.Format, doc)
	if err != nil {
		return nil, apierror.Internal("could not render dashboard report").Wrap(err)
	}
	defer func() { _ = stage.Close() }()
	receipt, err := stage.Receipt(renderContext)
	if err != nil {
		return nil, err
	}
	content, err := inlineDashboardStage(renderContext, stage)
	if err != nil {
		return nil, err
	}
	defer clear(content)
	if err := renderContext.Err(); err != nil {
		return nil, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return nil, apierror.Internal("could not generate report artifact id").Wrap(err)
	}
	var artifact *store.ReportArtifact
	if err := s.inTenant(r.WithContext(renderContext), func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		current, err := (store.DashboardReports{}).GetViewForReportPublication(ctx, sc, view.ID, dashboardActorID(r))
		if err != nil {
			return err
		}
		if !dashboardReportViewMatches(view, current) {
			return apierror.Conflict("dashboard changed while the report was generated; retry with its current definition")
		}
		input := store.ReportArtifactInput{
			ID: id, DashboardID: view.ID, Format: req.Format, MediaType: mediaType,
			Filename: reportFilename(view.Name, req.Format, now), Content: content, GeneratedBy: auditActor(r),
			AbsoluteFrom: definition.AbsoluteFrom, AbsoluteTo: definition.AbsoluteTo,
			Provenance: definition.Provenance, RedactionState: definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations,
		}
		var created *store.ReportArtifact
		if receipt.Bytes > maxInlineReportBytes {
			metadata, err := (store.DashboardReports{}).CreateDocumentChunkedArtifact(ctx, sc, input, stage)
			if err != nil {
				return err
			}
			created = &metadata.ReportArtifact
		} else {
			var err error
			created, err = (store.DashboardReports{}).CreateArtifact(ctx, sc, input)
			if err != nil {
				return err
			}
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_export", id, map[string]any{
			"dashboard_id": view.ID, "format": req.Format,
			"destination_id": reportInboxDestination, "redaction_state": definition.RedactionState,
			"body_bytes": receipt.Bytes, "body_sha256": receipt.SHA256,
		}); err != nil {
			return err
		}
		artifact = created
		return nil
	}); err != nil {
		return nil, err
	}
	return artifact, nil
}

func dashboardReportViewMatches(captured, current *store.DashboardView) bool {
	return captured != nil && current != nil && captured.ID == current.ID &&
		captured.TenantID == current.TenantID && captured.OwnerID == current.OwnerID &&
		captured.Name == current.Name && captured.Preset == current.Preset && captured.Shared == current.Shared &&
		captured.CreatedAt.Equal(current.CreatedAt) && captured.UpdatedAt.Equal(current.UpdatedAt) &&
		bytes.Equal(captured.Definition, current.Definition)
}

func renderReport(format string, doc reporting.Document) ([]byte, string, error) {
	if format == "csv" {
		content, err := reporting.RenderCSV(doc)
		return content, "text/csv", err
	}
	content, err := reporting.RenderPDF(doc)
	return content, "application/pdf", err
}

func dashboardTenantName(ctx context.Context, sc tenancy.Scope) (string, error) {
	var name string
	if err := sc.Q.QueryRow(ctx, `
		SELECT name FROM public.probectl_current_tenant_identity() WHERE id = $1`,
		sc.Tenant.String()).Scan(&name); err != nil {
		return "", err
	}
	return name, nil
}

var reportFilenameUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

func reportFilename(name, format string, generatedAt time.Time) string {
	base := strings.Trim(reportFilenameUnsafe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "dashboard"
	}
	if len(base) > 80 {
		base = base[:80]
	}
	return fmt.Sprintf("%s-%s.%s", base, generatedAt.UTC().Format("20060102T150405Z"), format)
}

func artifactView(item store.ReportArtifact) reportArtifactView {
	return reportArtifactView{
		ID: item.ID, DashboardID: item.DashboardID, ScheduleID: item.ScheduleID,
		Format: item.Format, MediaType: item.MediaType, Filename: item.Filename,
		GeneratedBy: item.GeneratedBy, GeneratedAt: item.GeneratedAt,
		AbsoluteFrom: item.AbsoluteFrom, AbsoluteTo: item.AbsoluteTo,
		Provenance: item.Provenance, RedactionState: item.RedactionState,
		CoverageLimitations: item.CoverageLimitations,
		DownloadURL:         "/v1/dashboard-report-artifacts/" + item.ID,
	}
}

func (s *Server) handleListDashboardReportArtifacts(w http.ResponseWriter, r *http.Request) error {
	return s.listCurrentReportArtifactMetadata(w, r)
}

func (s *Server) handleDownloadDashboardReportArtifact(w http.ResponseWriter, r *http.Request) error {
	return s.downloadDashboardReportArtifact(w, r)
}
