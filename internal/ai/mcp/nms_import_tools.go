// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

// Import results are named projections. Adding a storage column cannot
// silently publish source data to an MCP client.
type NMSImportRowResult struct {
	RowNumber     int64      `json:"row_number"`
	Kind          string     `json:"object_kind"`
	ExternalID    string     `json:"external_id"`
	Label         string     `json:"label,omitempty"`
	Address       string     `json:"address,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	ParentID      string     `json:"parent_external_id,omitempty"`
	LocationID    string     `json:"location_id,omitempty"`
	LocationLabel string     `json:"location_label,omitempty"`
	GroupIDs      []string   `json:"group_ids"`
	PollSeconds   int64      `json:"poll_seconds,omitempty"`
	Severity      string     `json:"severity,omitempty"`
	UnmappedCodes []string   `json:"unmapped_codes"`
	Action        string     `json:"action"`
	TargetID      string     `json:"target_entity_id,omitempty"`
	Reviewed      bool       `json:"reviewed"`
	State         string     `json:"state"`
	AppliedAt     *time.Time `json:"applied_at,omitempty"`
	BoundEntityID string     `json:"bound_entity_id,omitempty"`
	BindingPlanID string     `json:"binding_plan_id,omitempty"`
}

type NMSImportRowsResult struct {
	ContextID    string               `json:"context_id"`
	PlanID       string               `json:"plan_id"`
	SourceID     string               `json:"source_id"`
	SnapshotHash string               `json:"snapshot_hash"`
	RowCount     int64                `json:"row_count"`
	Items        []NMSImportRowResult `json:"items"`
	NextCursor   *int64               `json:"next_cursor,omitempty"`
}

type NMSImportDiffItemResult struct {
	RowNumber           int64    `json:"row_number"`
	Kind                string   `json:"object_kind"`
	ExternalID          string   `json:"external_id"`
	Action              string   `json:"action"`
	TargetID            string   `json:"target_entity_id,omitempty"`
	CurrentLabel        string   `json:"current_label,omitempty"`
	CurrentPollSeconds  int64    `json:"current_poll_seconds,omitempty"`
	ProposedLabel       string   `json:"proposed_label,omitempty"`
	ProposedPollSeconds int64    `json:"proposed_poll_seconds,omitempty"`
	ChangedFields       []string `json:"changed_fields"`
	UnmappedCodes       []string `json:"unmapped_codes"`
}

type NMSImportDryRunResult struct {
	ContextID    string                    `json:"context_id"`
	PlanID       string                    `json:"plan_id"`
	SnapshotHash string                    `json:"snapshot_hash"`
	ReviewHash   string                    `json:"review_hash"`
	RowCount     int64                     `json:"row_count"`
	Items        []NMSImportDiffItemResult `json:"items"`
	NextCursor   *int64                    `json:"next_cursor,omitempty"`
}

type NMSImportPollTargetInput struct {
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	ItemID        string `json:"item_external_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
}

type NMSImportPollTargetResult struct {
	TenantID      string `json:"tenant_id"`
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	ItemID        string `json:"item_external_id"`
	HostID        string `json:"host_external_id"`
	EntityID      string `json:"entity_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
	PollSeconds   int64  `json:"poll_seconds"`
	PlanID        string `json:"plan_id"`
	Revision      int64  `json:"revision"`
}

type NMSImportAlertTargetInput struct {
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	RuleID        string `json:"rule_external_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
}

type NMSImportAlertTargetResult struct {
	TenantID      string `json:"tenant_id"`
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	RuleID        string `json:"rule_external_id"`
	DeviceID      string `json:"device_external_id"`
	EntityID      string `json:"entity_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
	PlanID        string `json:"plan_id"`
	SnapshotHash  string `json:"snapshot_hash"`
	Name          string `json:"name"`
	Severity      string `json:"severity"`
	RuleKind      string `json:"rule_kind"`
	Enabled       bool   `json:"enabled"`
}

type NMSImportAlertApplyInput struct {
	ContextID     string `json:"context_id"`
	SourceID      string `json:"source_id"`
	RuleID        string `json:"rule_external_id"`
	AgentID       string `json:"agent_id"`
	TargetAddress string `json:"target_address"`
	PlanID        string `json:"plan_id"`
	SnapshotHash  string `json:"snapshot_hash"`
	EntityID      string `json:"entity_id"`
}

type NMSImportAlertApplyResult struct {
	AlertRuleID string `json:"alert_rule_id"`
	Created     bool   `json:"created"`
}

type NMSImportPollProposalsInput struct {
	ContextID string `json:"context_id"`
	SourceID  string `json:"source_id"`
	Cursor    string `json:"cursor,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type NMSImportPollProposalResult struct {
	ItemID      string    `json:"item_external_id"`
	HostID      string    `json:"host_external_id"`
	PollSeconds int64     `json:"poll_seconds"`
	PlanID      string    `json:"plan_id"`
	Revision    int64     `json:"revision"`
	AppliedAt   time.Time `json:"applied_at"`
}

type NMSImportPollProposalsResult struct {
	ContextID  string                        `json:"context_id"`
	SourceID   string                        `json:"source_id"`
	Items      []NMSImportPollProposalResult `json:"items"`
	NextCursor *string                       `json:"next_cursor,omitempty"`
}

type NMSImportRowsInput struct {
	ContextID string `json:"context_id"`
	PlanID    string `json:"plan_id"`
	Cursor    *int64 `json:"cursor,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type NMSImportDryRunInput struct {
	ContextID  string `json:"context_id"`
	PlanID     string `json:"plan_id"`
	ReviewHash string `json:"review_hash"`
	Cursor     *int64 `json:"cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

type NMSImportExportStartInput struct {
	ContextID   string `json:"context_id"`
	SourceKind  string `json:"source_kind"`
	InstanceRef string `json:"instance_ref"`
}

type NMSImportExportStartResult struct {
	PlanID  string `json:"plan_id"`
	State   string `json:"state"`
	Preview bool   `json:"preview"`
}

type NMSImportExportPageInput struct {
	ContextID  string          `json:"context_id"`
	PlanID     string          `json:"plan_id"`
	Resource   string          `json:"resource"`
	PageNumber int64           `json:"page_number"`
	FirstRow   int64           `json:"first_row"`
	Page       json.RawMessage `json:"page"`
}

type NMSImportExportPageResult struct {
	PageHash string `json:"page_hash"`
}

type NMSImportExportSealInput struct {
	ContextID     string `json:"context_id"`
	PlanID        string `json:"plan_id"`
	ExpectedPages int64  `json:"expected_pages"`
	ExpectedRows  int64  `json:"expected_rows"`
}

type NMSImportExportSealResult struct {
	State        string `json:"state"`
	SnapshotHash string `json:"snapshot_hash"`
	Preview      bool   `json:"preview"`
}

type NMSImportBackend interface {
	NMSImportRows(context.Context, *auth.Principal, NMSImportRowsInput) (NMSImportRowsResult, error)
	NMSImportDryRun(context.Context, *auth.Principal, NMSImportDryRunInput) (NMSImportDryRunResult, error)
	NMSImportPollProposals(context.Context, *auth.Principal, NMSImportPollProposalsInput) (NMSImportPollProposalsResult, error)
	NMSImportPollTarget(context.Context, *auth.Principal, NMSImportPollTargetInput) (NMSImportPollTargetResult, error)
	NMSImportAlertTarget(context.Context, *auth.Principal, NMSImportAlertTargetInput) (NMSImportAlertTargetResult, error)
	NMSImportAlertApply(context.Context, *auth.Principal, NMSImportAlertApplyInput) (NMSImportAlertApplyResult, error)
	NMSImportExportStart(context.Context, *auth.Principal, NMSImportExportStartInput) (NMSImportExportStartResult, error)
	NMSImportExportPage(context.Context, *auth.Principal, NMSImportExportPageInput) (NMSImportExportPageResult, error)
	NMSImportExportSeal(context.Context, *auth.Principal, NMSImportExportSealInput) (NMSImportExportSealResult, error)
}

func WithNMSImportBackend(backend NMSImportBackend) Option {
	return func(s *Server) {
		if backend == nil {
			return
		}
		for _, tool := range buildNMSImportTools(backend) {
			s.tools[tool.Name] = tool
			s.order = append(s.order, tool.Name)
		}
	}
}

func nmsImportTool[A, R any](name, description string, schema json.RawMessage,
	invoke func(context.Context, *auth.Principal, A) (R, error)) Tool {
	return nmsImportToolWithPermission(name, description, schema, "nms.import.read", invoke)
}

func nmsImportToolWithPermission[A, R any](name, description string,
	schema json.RawMessage, permission string,
	invoke func(context.Context, *auth.Principal, A) (R, error)) Tool {
	return Tool{Name: name, Description: description, Permission: permission,
		InputSchema: schema, RequiresUser: true,
		Invoke: func(ctx context.Context, p *auth.Principal, raw json.RawMessage) (any, error) {
			var args A
			if err := decodeNativeArgs(raw, &args); err != nil {
				return nil, argErr("invalid import arguments")
			}
			return invoke(ctx, p, args)
		}}
}

func buildNMSImportTools(b NMSImportBackend) []Tool {
	return []Tool{
		nmsImportTool("nms_import_rows", "Page one tenant-owned redacted NMS import plan and its unmapped reasons.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"plan_id":{"type":"string"},"cursor":{"type":"integer","minimum":-1},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id","plan_id"],"additionalProperties":false}`), b.NMSImportRows),
		nmsImportTool("nms_import_dry_run", "Page a frozen reviewed destination comparison; this tool never applies choices.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"plan_id":{"type":"string"},"review_hash":{"type":"string"},"cursor":{"type":"integer","minimum":-1},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id","plan_id","review_hash"],"additionalProperties":false}`), b.NMSImportDryRun),
		nmsImportTool("nms_import_poll_proposals", "Page inert applied Zabbix SNMP cadence proposals from one tenant source; no credential or agent assignment.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"source_id":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["context_id","source_id"],"additionalProperties":false}`), b.NMSImportPollProposals),
		nmsImportTool("nms_import_poll_target", "Verify one reviewed polling proposal against an exact current device-agent target; no credential or activation.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"source_id":{"type":"string"},"item_external_id":{"type":"string"},"agent_id":{"type":"string"},"target_address":{"type":"string"}},"required":["context_id","source_id","item_external_id","agent_id","target_address"],"additionalProperties":false}`), b.NMSImportPollTarget),
		nmsImportTool("nms_import_alert_target", "Verify one finite disabled LibreNMS port-down rule against the exact current agent target; no source SQL or delivery operation.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"source_id":{"type":"string"},"rule_external_id":{"type":"string"},"agent_id":{"type":"string"},"target_address":{"type":"string"}},"required":["context_id","source_id","rule_external_id","agent_id","target_address"],"additionalProperties":false}`), b.NMSImportAlertTarget),
		nmsImportToolWithPermission("nms_import_alert_apply", "After an exact reviewed target selection, create only a disabled channel-free native alert; this never enables delivery.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"source_id":{"type":"string"},"rule_external_id":{"type":"string"},"agent_id":{"type":"string"},"target_address":{"type":"string"},"plan_id":{"type":"string"},"snapshot_hash":{"type":"string"},"entity_id":{"type":"string"}},"required":["context_id","source_id","rule_external_id","agent_id","target_address","plan_id","snapshot_hash","entity_id"],"additionalProperties":false}`),
			"nms.import.write", b.NMSImportAlertApply),
		nmsImportToolWithPermission("nms_import_export_start", "Start an inert Orion or PRTG documented-export preview in one authorized routing context.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"source_kind":{"type":"string","enum":["orion","prtg"]},"instance_ref":{"type":"string"}},"required":["context_id","source_kind","instance_ref"],"additionalProperties":false}`),
			"nms.import.write", b.NMSImportExportStart),
		nmsImportToolWithPermission("nms_import_export_page", "Capture one bounded, untrusted Orion or PRTG JSON page into an inert tenant plan; only its redacted receipt returns.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"plan_id":{"type":"string"},"resource":{"type":"string","enum":["nodes","devices","groups","rules","probes"]},"page_number":{"type":"integer","minimum":0},"first_row":{"type":"integer","minimum":0},"page":{"type":["object","array"]}},"required":["context_id","plan_id","resource","page_number","first_row","page"],"additionalProperties":false}`),
			"nms.import.write", b.NMSImportExportPage),
		nmsImportToolWithPermission("nms_import_export_seal", "Seal submitted documented-export pages as an inert preview, with no claim of unseen source completeness.",
			json.RawMessage(`{"type":"object","properties":{"context_id":{"type":"string"},"plan_id":{"type":"string"},"expected_pages":{"type":"integer","minimum":1},"expected_rows":{"type":"integer","minimum":0}},"required":["context_id","plan_id","expected_pages","expected_rows"],"additionalProperties":false}`),
			"nms.import.write", b.NMSImportExportSeal),
	}
}
