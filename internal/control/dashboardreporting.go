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
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/reporting"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const (
	reportInboxDestination    = "tenant-report-inbox"
	dashboardManifestVersion  = "probectl.io/dashboard/v1"
	dashboardManifestKind     = "Dashboard"
	maxDashboardManifestBytes = 64 << 10
	maxReportMetrics          = 100
	maxReportDisclosure       = 20
)

type dashboardDefinition struct {
	AbsoluteFrom        time.Time         `json:"absolute_from"`
	AbsoluteTo          time.Time         `json:"absolute_to"`
	Provenance          []string          `json:"provenance"`
	RedactionState      string            `json:"redaction_state"`
	CoverageLimitations []string          `json:"coverage_limitations"`
	Metrics             map[string]string `json:"metrics"`
}

type dashboardCreateRequest struct {
	Name       string              `json:"name"`
	Preset     string              `json:"preset"`
	Shared     bool                `json:"shared"`
	Definition dashboardDefinition `json:"definition"`
}

// dashboardManifest is the stable, portable representation of a native saved
// dashboard. Identity and storage fields are absent by construction: the
// importing server derives tenant, owner, id, and timestamps.
type dashboardManifest struct {
	APIVersion string                    `json:"api_version"`
	Kind       string                    `json:"kind"`
	Metadata   dashboardManifestMetadata `json:"metadata"`
	Spec       dashboardManifestSpec     `json:"spec"`
}

type dashboardManifestMetadata struct {
	Name string `json:"name"`
}

type dashboardManifestSpec struct {
	Preset     string                      `json:"preset"`
	Shared     bool                        `json:"shared"`
	Definition dashboardManifestDefinition `json:"definition"`
}

type dashboardManifestDefinition struct {
	AbsoluteFrom        time.Time                 `json:"absolute_from"`
	AbsoluteTo          time.Time                 `json:"absolute_to"`
	Provenance          []string                  `json:"provenance"`
	RedactionState      string                    `json:"redaction_state"`
	CoverageLimitations []string                  `json:"coverage_limitations"`
	Metrics             []dashboardManifestMetric `json:"metrics"`
}

type dashboardManifestMetric struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dashboardManifestImportRequest struct {
	Manifest dashboardManifest `json:"manifest"`
	Confirm  bool              `json:"confirm"`
}

type dashboardManifestPreview struct {
	Name                    string    `json:"name"`
	Preset                  string    `json:"preset"`
	Shared                  bool      `json:"shared"`
	AbsoluteFrom            time.Time `json:"absolute_from"`
	AbsoluteTo              time.Time `json:"absolute_to"`
	MetricCount             int       `json:"metric_count"`
	ProvenanceCount         int       `json:"provenance_count"`
	CoverageLimitationCount int       `json:"coverage_limitation_count"`
}

type dashboardManifestImportResponse struct {
	Status    string                   `json:"status"`
	Manifest  dashboardManifest        `json:"manifest"`
	Preview   dashboardManifestPreview `json:"preview"`
	Dashboard *store.DashboardView     `json:"dashboard,omitempty"`
}

type reportScheduleCreateRequest struct {
	DashboardID   string    `json:"dashboard_id"`
	Name          string    `json:"name"`
	Format        string    `json:"format"`
	Cadence       string    `json:"cadence"`
	DestinationID string    `json:"destination_id"`
	FirstRunAt    time.Time `json:"first_run_at"`
}

type reportGenerateRequest struct {
	DashboardID string `json:"dashboard_id"`
	Format      string `json:"format"`
}

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
	if d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.After(d.AbsoluteFrom) {
		return apierror.Validation("definition requires an absolute_from earlier than absolute_to")
	}
	if d.AbsoluteTo.Sub(d.AbsoluteFrom) > 366*24*time.Hour {
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
	clean, err = sanitizeDashboardCreate(clean, view.TenantID, view.OwnerID)
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
	clean, err := dashboardManifestToCreate(body.Manifest)
	if err != nil {
		return err
	}

	var response dashboardManifestImportResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
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
	id, err := crypto.UUIDv4()
	if err != nil {
		return apierror.Internal("could not generate report schedule id").Wrap(err)
	}
	var schedule *store.ReportSchedule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		created, err := (store.DashboardReports{}).CreateSchedule(ctx, sc, store.ReportScheduleInput{
			ID: id, DashboardID: clean.DashboardID, OwnerID: dashboardActorID(r), Name: clean.Name,
			Format: clean.Format, Cadence: clean.Cadence, DestinationID: clean.DestinationID,
			NextRunAt: clean.FirstRunAt,
		})
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_schedule", id, map[string]any{
			"dashboard_id": clean.DashboardID, "format": clean.Format,
			"cadence": clean.Cadence, "destination_id": clean.DestinationID,
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
		"outbound_default": false,
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
	id, err := crypto.UUIDv4()
	if err != nil {
		return apierror.Internal("could not generate report artifact id").Wrap(err)
	}
	var artifact *store.ReportArtifact
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		view, err := (store.DashboardReports{}).GetView(ctx, sc, req.DashboardID, dashboardActorID(r))
		if err != nil {
			return err
		}
		var definition dashboardDefinition
		if err := json.Unmarshal(view.Definition, &definition); err != nil {
			return apierror.Internal("stored dashboard definition is invalid").Wrap(err)
		}
		if err := cleanDashboardDefinition(&definition); err != nil {
			return apierror.Internal("stored dashboard definition failed validation").Wrap(err)
		}
		tenantName, err := dashboardTenantName(ctx, sc)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		doc := reporting.Document{
			Title: view.Name, Preset: view.Preset, TenantName: tenantName,
			TenantScope: sc.Tenant.String(), AbsoluteFrom: definition.AbsoluteFrom,
			AbsoluteTo: definition.AbsoluteTo, GeneratedAt: now, GeneratedBy: auditActor(r),
			Provenance: definition.Provenance, RedactionState: definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics,
		}
		content, mediaType, err := renderReport(req.Format, doc)
		if err != nil {
			return apierror.Internal("could not render dashboard report").Wrap(err)
		}
		filename := reportFilename(view.Name, req.Format, now)
		created, err := (store.DashboardReports{}).CreateArtifact(ctx, sc, store.ReportArtifactInput{
			ID: id, DashboardID: view.ID, Format: req.Format, MediaType: mediaType,
			Filename: filename, Content: content, GeneratedBy: auditActor(r),
			AbsoluteFrom: definition.AbsoluteFrom, AbsoluteTo: definition.AbsoluteTo,
			Provenance: definition.Provenance, RedactionState: definition.RedactionState,
			CoverageLimitations: definition.CoverageLimitations,
		})
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_export", id, map[string]any{
			"dashboard_id": view.ID, "format": req.Format,
			"destination_id": reportInboxDestination, "redaction_state": definition.RedactionState,
		}); err != nil {
			return err
		}
		artifact = created
		return nil
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/dashboard-report-artifacts/"+id)
	writeJSON(w, http.StatusCreated, artifactView(*artifact))
	return nil
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
	var items []store.ReportArtifact
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, err = (store.DashboardReports{}).ListArtifacts(ctx, sc, dashboardActorID(r))
		return err
	}); err != nil {
		return err
	}
	views := make([]reportArtifactView, 0, len(items))
	for _, item := range items {
		views = append(views, artifactView(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
	return nil
}

func (s *Server) handleDownloadDashboardReportArtifact(w http.ResponseWriter, r *http.Request) error {
	var artifact *store.ReportArtifact
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		item, err := (store.DashboardReports{}).GetArtifact(ctx, sc, r.PathValue("id"), dashboardActorID(r))
		if err != nil {
			return err
		}
		if err := s.recordAudit(ctx, sc, r, "dashboard.report_download", item.ID, map[string]any{
			"dashboard_id": item.DashboardID, "format": item.Format,
		}); err != nil {
			return err
		}
		artifact = item
		return nil
	}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", artifact.MediaType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", artifact.Filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(artifact.Content)
	return err
}
