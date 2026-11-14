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
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mcpReportBackend struct{ server *Server }

var _ mcp.ReportBackend = mcpReportBackend{}

func (b mcpReportBackend) current(ctx context.Context, actor *auth.Principal, write bool) (context.Context, *auth.Principal, error) {
	if b.server == nil || b.server.pool == nil {
		return nil, nil, apierror.Unavailable("report services are unavailable")
	}
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, nil, apierror.Forbidden("an authenticated tenant user is required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != actor.TenantID {
		return nil, nil, apierror.Forbidden("report credential and tenant context disagree")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	authority, err := loadCurrentUserAuthority(ctx, b.server.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, nil, err
	}
	ctx, principal, err := authority.requestContext(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	permissions := []string{"metrics.read", permAIQuery}
	if write {
		permissions = append(permissions, permMetricsWrite)
	}
	for _, permission := range permissions {
		if err := b.server.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
			return nil, nil, err
		}
	}
	// Delegated services repeat fresh checks. Carry the actual credential,
	// not the expanded current user, so those checks cannot adopt a wider
	// bearer ceiling from this refresh's full role projection.
	credential := auth.ClonePrincipal(actor)
	return auth.WithPrincipal(ctx, credential), credential, nil
}

type reportMetadataWriter struct {
	header        http.Header
	body          bytes.Buffer
	limit, status int
	err           error
}

func (w *reportMetadataWriter) Header() http.Header { return w.header }
func (w *reportMetadataWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *reportMetadataWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(data) > w.limit-w.body.Len() {
		w.err = apierror.RateLimited("report metadata exceeds the current native transport budget")
		return 0, w.err
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

// Call the concrete shared handler, never the HTTP router or a network peer.
// Current authorization is repeated here because handlers rely on their REST
// route guard. The bounded response is strictly decoded into a named contract;
// unknown fields, malformed projections and partial writes never escape MCP.
func invokeReportHandler[T any](ctx context.Context, b mcpReportBackend, p *auth.Principal, write bool, method, path, id string, input any, handler func(http.ResponseWriter, *http.Request) error) (T, error) {
	var result T
	ctx, principal, err := b.current(ctx, p, write)
	if err != nil {
		return result, err
	}
	if err := b.server.flowRenderBudget.Validate(); err != nil {
		return result, apierror.Unavailable("report native cost policy is unavailable")
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return result, err
		}
		if len(data) > 64<<10 {
			return result, apierror.Validation("report arguments exceed the native document budget")
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, principal), method, path, body)
	if err != nil {
		return result, err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.SetPathValue("id", id)
	response := &reportMetadataWriter{header: make(http.Header), limit: b.server.flowRenderBudget.SourceBytes}
	if err := handler(response, request); err != nil {
		return result, reportGenerationError(err)
	}
	if response.err != nil {
		return result, response.err
	}
	if response.status < 200 || response.status >= 300 {
		return result, apierror.Unavailable("report metadata response is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(response.body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, apierror.Internal("report metadata projection is invalid").Wrap(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, apierror.Internal("report metadata projection has trailing data")
	}
	return result, nil
}

func (b mcpReportBackend) ReportDashboards(ctx context.Context, p *auth.Principal) (mcp.ReportDashboardList, error) {
	return invokeReportHandler[mcp.ReportDashboardList](ctx, b, p, false, http.MethodGet, "/v1/dashboards", "", nil, b.server.handleListDashboards)
}
func (b mcpReportBackend) ReportDashboard(ctx context.Context, p *auth.Principal, id string) (mcp.ReportDashboard, error) {
	return invokeReportHandler[mcp.ReportDashboard](ctx, b, p, false, http.MethodGet, "/v1/dashboards/"+url.PathEscape(id), id, nil, b.server.handleGetDashboard)
}
func (b mcpReportBackend) ReportDashboardSave(ctx context.Context, p *auth.Principal, input reporting.DashboardCreateInput) (mcp.ReportDashboard, error) {
	return invokeReportHandler[mcp.ReportDashboard](ctx, b, p, true, http.MethodPost, "/v1/dashboards", "", input, b.server.handleCreateDashboard)
}
func (b mcpReportBackend) ReportDashboardExport(ctx context.Context, p *auth.Principal, id string) (reporting.DashboardManifest, error) {
	return invokeReportHandler[reporting.DashboardManifest](ctx, b, p, false, http.MethodGet, "/v1/dashboards/"+url.PathEscape(id)+"/manifest", id, nil, b.server.handleExportDashboardManifest)
}
func (b mcpReportBackend) ReportDashboardImport(ctx context.Context, p *auth.Principal, input reporting.DashboardManifestImportInput) (mcp.ReportImportResult, error) {
	return invokeReportHandler[mcp.ReportImportResult](ctx, b, p, true, http.MethodPost, "/v1/dashboard-manifests/import", "", input, b.server.handleImportDashboardManifest)
}
func (b mcpReportBackend) ReportSchedules(ctx context.Context, p *auth.Principal) (mcp.ReportScheduleList, error) {
	return invokeReportHandler[mcp.ReportScheduleList](ctx, b, p, false, http.MethodGet, "/v1/dashboard-report-schedules", "", nil, b.server.handleListReportSchedules)
}
func (b mcpReportBackend) ReportScheduleCreate(ctx context.Context, p *auth.Principal, input reporting.ReportScheduleInput) (mcp.ReportSchedule, error) {
	return invokeReportHandler[mcp.ReportSchedule](ctx, b, p, true, http.MethodPost, "/v1/dashboard-report-schedules", "", input, b.server.handleCreateReportSchedule)
}
func (b mcpReportBackend) ReportScheduleUpdate(ctx context.Context, p *auth.Principal, input mcp.ReportScheduleUpdateInput) (mcp.ReportSchedule, error) {
	body := struct {
		DestinationID          *string `json:"destination_id,omitempty"`
		Enabled                *bool   `json:"enabled,omitempty"`
		ProviderTriggerAllowed *bool   `json:"provider_trigger_allowed,omitempty"`
	}{input.DestinationID, input.Enabled, input.ProviderTriggerAllowed}
	return invokeReportHandler[mcp.ReportSchedule](ctx, b, p, true, http.MethodPatch, "/v1/dashboard-report-schedules/"+url.PathEscape(input.ID), input.ID, body, b.server.handleUpdateReportSchedule)
}
func (b mcpReportBackend) ReportGenerate(ctx context.Context, p *auth.Principal, input reporting.ReportGenerateInput) (mcp.ReportArtifact, error) {
	return invokeReportHandler[mcp.ReportArtifact](ctx, b, p, true, http.MethodPost, "/v1/dashboard-reports", "", input, b.server.handleGenerateDashboardReport)
}
func (b mcpReportBackend) ReportArtifacts(ctx context.Context, p *auth.Principal, input mcp.ReportArtifactListInput) (mcp.ReportArtifactList, error) {
	query := url.Values{}
	if input.Limit != nil {
		query.Set("limit", strconv.Itoa(*input.Limit))
	}
	if input.Cursor != "" {
		query.Set("cursor", input.Cursor)
	}
	path := "/v1/dashboard-report-artifacts"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return invokeReportHandler[mcp.ReportArtifactList](ctx, b, p, false, http.MethodGet, path, "", nil, b.server.handleListDashboardReportArtifacts)
}

func (b mcpReportBackend) ReportArtifactLink(ctx context.Context, p *auth.Principal, id string) (mcp.ReportArtifactLink, error) {
	var result mcp.ReportArtifactLink
	ctx, principal, err := b.current(ctx, p, false)
	if err != nil {
		return result, err
	}
	budget := flowstore.ExplorerQueryBudget(b.server.flowStore)
	if err := budget.Validate(); err != nil {
		return result, apierror.Unavailable("report metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if b.server.fairnessGate == nil {
		return result, apierror.Unavailable("report metadata admission is unavailable")
	}
	release, err := b.server.fairnessGate.BeginQuery(ctx, principal.TenantID)
	if err != nil {
		return result, tagQueryAdmissionError(err)
	}
	defer release()
	var metadata *store.ReportArtifactMetadata
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), b.server.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		metadata, err = (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, id, principal.UserID)
		if err != nil {
			return err
		}
		if metadata.BodyStorage == "inline" && len(metadata.SourceCapture) == 0 {
			return nil
		}
		metadata, err = b.server.currentReportArtifactMetadata(ctx, sc, principal, id, principal.UserID)
		if err != nil {
			return err
		}
		if metadata == nil {
			return apierror.NotFound("dashboard report artifact not found")
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	view := artifactMetadataView(*metadata)
	// The same explicit JSON contract used by list/generation prevents a store
	// object or private source envelope from becoming an MCP projection.
	raw, err := json.Marshal(view)
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result.Artifact); err != nil {
		return result, apierror.Internal("report link metadata projection is invalid").Wrap(err)
	}
	if len(result.Artifact.DownloadURL) == 0 {
		return result, errors.New("report link is unavailable")
	}
	result.AuthenticationRequired = true
	result.Integrity = "stored metadata; authenticated download verifies the complete body"
	return result, nil
}
