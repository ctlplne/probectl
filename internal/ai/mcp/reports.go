// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
)

// ReportBackend reuses current tenant reporting services. Binary content never
// crosses this metadata seam: its URI still requires authenticated REST reads.
type ReportBackend interface {
	ReportDashboards(context.Context, *auth.Principal) (ReportDashboardList, error)
	ReportDashboard(context.Context, *auth.Principal, string) (ReportDashboard, error)
	ReportDashboardSave(context.Context, *auth.Principal, reporting.DashboardCreateInput) (ReportDashboard, error)
	ReportDashboardExport(context.Context, *auth.Principal, string) (reporting.DashboardManifest, error)
	ReportDashboardImport(context.Context, *auth.Principal, reporting.DashboardManifestImportInput) (ReportImportResult, error)
	ReportSchedules(context.Context, *auth.Principal) (ReportScheduleList, error)
	ReportScheduleCreate(context.Context, *auth.Principal, reporting.ReportScheduleInput) (ReportSchedule, error)
	ReportScheduleUpdate(context.Context, *auth.Principal, ReportScheduleUpdateInput) (ReportSchedule, error)
	ReportGenerate(context.Context, *auth.Principal, reporting.ReportGenerateInput) (ReportArtifact, error)
	ReportArtifacts(context.Context, *auth.Principal, ReportArtifactListInput) (ReportArtifactList, error)
	ReportArtifactLink(context.Context, *auth.Principal, string) (ReportArtifactLink, error)
}

type ReportDashboard struct {
	ID         string                        `json:"id"`
	TenantID   string                        `json:"tenant_id"`
	OwnerID    string                        `json:"owner_id"`
	Name       string                        `json:"name"`
	Preset     string                        `json:"preset"`
	Shared     bool                          `json:"shared"`
	Definition reporting.DashboardDefinition `json:"definition"`
	CreatedAt  time.Time                     `json:"created_at"`
	UpdatedAt  time.Time                     `json:"updated_at"`
}
type ReportDashboardList struct {
	Items []ReportDashboard `json:"items"`
}
type ReportImportResult struct {
	Status    string                             `json:"status"`
	Manifest  reporting.DashboardManifest        `json:"manifest"`
	Preview   reporting.DashboardManifestPreview `json:"preview"`
	Dashboard *ReportDashboard                   `json:"dashboard,omitempty"`
}
type ReportSchedule struct {
	ProviderTriggerAllowed    bool       `json:"provider_trigger_allowed"`
	ProviderRequestID         *string    `json:"provider_request_id,omitempty"`
	ProviderOriginalNextRunAt *time.Time `json:"provider_original_next_run_at,omitempty"`
	ID                        string     `json:"id"`
	TenantID                  string     `json:"tenant_id"`
	DashboardID               string     `json:"dashboard_id"`
	OwnerID                   string     `json:"owner_id"`
	Name                      string     `json:"name"`
	Format                    string     `json:"format"`
	Cadence                   string     `json:"cadence"`
	DestinationID             string     `json:"destination_id"`
	Enabled                   bool       `json:"enabled"`
	NextRunAt                 time.Time  `json:"next_run_at"`
	LastRunAt                 *time.Time `json:"last_run_at,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}
type ReportDestination struct {
	Description string `json:"description,omitempty"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Outbound    bool   `json:"outbound"`
	Ready       bool   `json:"ready"`
}
type ReportScheduleList struct {
	ProviderTriggerAvailable bool                `json:"provider_trigger_available"`
	Items                    []ReportSchedule    `json:"items"`
	Destinations             []ReportDestination `json:"destinations"`
	OutboundDefault          bool                `json:"outbound_default"`
}
type ReportScheduleUpdateInput struct {
	DestinationID          *string `json:"destination_id,omitempty"`
	ProviderTriggerAllowed *bool   `json:"provider_trigger_allowed,omitempty"`
	ID                     string  `json:"id"`
	Enabled                *bool   `json:"enabled,omitempty"`
}
type ReportArtifact struct {
	EmailDelivery       *reporting.ReportEmailDelivery `json:"email_delivery,omitempty"`
	ID                  string                         `json:"id"`
	DashboardID         string                         `json:"dashboard_id"`
	ScheduleID          *string                        `json:"schedule_id,omitempty"`
	Format              string                         `json:"format"`
	MediaType           string                         `json:"media_type"`
	Filename            string                         `json:"filename"`
	GeneratedBy         string                         `json:"generated_by"`
	GeneratedAt         time.Time                      `json:"generated_at"`
	AbsoluteFrom        time.Time                      `json:"absolute_from"`
	AbsoluteTo          time.Time                      `json:"absolute_to"`
	Provenance          []string                       `json:"provenance"`
	RedactionState      string                         `json:"redaction_state"`
	CoverageLimitations []string                       `json:"coverage_limitations"`
	DownloadURL         string                         `json:"download_url"`
	BodyBytes           int64                          `json:"body_bytes,omitempty"`
	BodySHA256          string                         `json:"body_sha256,omitempty"`
}
type ReportArtifactListInput struct {
	Limit  *int   `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}
type ReportArtifactList struct {
	Items      []ReportArtifact `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}
type ReportArtifactLink struct {
	Artifact               ReportArtifact `json:"artifact"`
	AuthenticationRequired bool           `json:"authentication_required"`
	// The hash describes stored metadata; download independently verifies bytes.
	Integrity string `json:"integrity"`
}
type reportIDInput struct {
	ID string `json:"id"`
}
type reportEmptyInput struct{}

// Reporting services own source admission through publication. Do not attach
// another outer query slot to these tools or one-slot tenants would deadlock.
func reportTool[A, R any](name, description string, schema json.RawMessage, write bool, invoke func(context.Context, *auth.Principal, A) (R, error)) Tool {
	var contract struct {
		Required []string `json:"required"`
	}
	_ = json.Unmarshal(schema, &contract)
	permissions := []string{"ai.query"}
	if write {
		permissions = append(permissions, "metrics.write")
	}
	return Tool{Name: name, Description: description, InputSchema: schema, Permission: "metrics.read", ExtraPermissions: permissions, Native: true, RequiresUser: true, Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, apierror.Validation("invalid native report arguments")
		}
		for _, name := range contract.Required {
			if value, ok := fields[name]; !ok || strings.TrimSpace(string(value)) == "null" {
				return nil, apierror.Validation("required report argument is missing")
			}
		}
		var input A
		if err := decodeBoundedNativeArgsWithMaps(raw, &input, 64<<10, reportArgumentMap); err != nil {
			return nil, apierror.Validation("invalid native report arguments")
		}
		return invoke(ctx, p, input)
	}}
}

func reportArgumentMap(typ reflect.Type) bool {
	return typ == reflect.TypeFor[map[string]reporting.FlowSourceRef]() ||
		typ == reflect.TypeFor[map[string]string]()
}

func WithReportBackend(backend ReportBackend, schemas NativeFlowSchemas) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		tools := []Tool{
			reportTool("report_dashboards", "List current owned/shared tenant dashboard configuration.", schemas["report_dashboards"], false, func(ctx context.Context, p *auth.Principal, _ reportEmptyInput) (ReportDashboardList, error) {
				return backend.ReportDashboards(ctx, p)
			}),
			reportTool("report_dashboard", "Read one current owned/shared dashboard.", schemas["report_dashboard"], false, func(ctx context.Context, p *auth.Principal, in reportIDInput) (ReportDashboard, error) {
				return backend.ReportDashboard(ctx, p, in.ID)
			}),
			reportTool("report_dashboard_save", "Save an audited tenant dashboard; source bindings require current destination authority.", schemas["report_dashboard_save"], true, backend.ReportDashboardSave),
			reportTool("report_dashboard_export", "Export a portable redacted native dashboard with source slots and no local source identities.", schemas["report_dashboard_export"], false, func(ctx context.Context, p *auth.Principal, in reportIDInput) (reporting.DashboardManifest, error) {
				return backend.ReportDashboardExport(ctx, p, in.ID)
			}),
			reportTool("report_dashboard_import", "Preview by default; confirm explicitly to create a native dashboard with current destination source bindings.", schemas["report_dashboard_import"], true, backend.ReportDashboardImport),
			reportTool("report_schedules", "List this user's report schedules and local destinations.", schemas["report_schedules"], false, func(ctx context.Context, p *auth.Principal, _ reportEmptyInput) (ReportScheduleList, error) {
				return backend.ReportSchedules(ctx, p)
			}),
			reportTool("report_schedule_create", "Create an audited local-inbox schedule with current owner authority checked at delivery.", schemas["report_schedule_create"], true, backend.ReportScheduleCreate),
			reportTool("report_schedule_update", "Update an owned schedule or configured delivery target; source work and provider-trigger grants require current authority, while local-inbox/provider revocation delegates no source read.", schemas["report_schedule_update"], true, backend.ReportScheduleUpdate),
			reportTool("report_generate", "Generate a complete audited report under current source, lifecycle and cost checks; fetch binary bytes through the authenticated download URL.", schemas["report_generate"], true, backend.ReportGenerate),
			reportTool("report_artifacts", "List current-authorized report metadata, never report bytes or stored source grants.", schemas["report_artifacts"], false, func(ctx context.Context, p *auth.Principal, input ReportArtifactListInput) (ReportArtifactList, error) {
				return backend.ReportArtifacts(ctx, p, input)
			}),
			reportTool("report_artifact_link", "Read current-authorized artifact metadata and its authenticated REST URI; metadata alone does not verify body integrity or grant future access.", schemas["report_artifact_link"], false, func(ctx context.Context, p *auth.Principal, in reportIDInput) (ReportArtifactLink, error) {
				return backend.ReportArtifactLink(ctx, p, in.ID)
			}),
		}
		for _, tool := range tools {
			if !json.Valid(tool.InputSchema) {
				s.log.Error("report tool schema is unavailable", "tool", tool.Name)
				return
			}
		}
		s.nativeEnabled = true
		for _, tool := range tools {
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}
