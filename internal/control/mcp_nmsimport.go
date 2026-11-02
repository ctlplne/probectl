// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var _ mcp.NMSImportBackend = mcpNMSImportBackend{}

type mcpNMSImportBackend struct {
	pool         *pgxpool.Pool
	policyLoader mcp.PolicyLoader
	owner        *Server
}

// The principal selects the tenant before even the context lookup. The
// routing-context ABAC policy is checked before reading a plan or its rows.
func (b mcpNMSImportBackend) readScope(ctx context.Context, p *auth.Principal,
	contextID string) (context.Context, string, error) {
	return b.scope(ctx, p, contextID, permNMSImportRead)
}

func (b mcpNMSImportBackend) scope(ctx context.Context, p *auth.Principal,
	contextID, permission string) (context.Context, string, error) {
	if p == nil || p.TenantID == "" {
		return nil, "", apierror.Forbidden("tenant identity is required")
	}
	scope, err := (entity.Scope{TenantID: p.TenantID, ContextID: contextID}).Normalize()
	if err != nil {
		return nil, "", apierror.BadRequest("invalid import routing context")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(scope.TenantID))
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p, scope, permission); err != nil {
		return nil, "", err
	}
	return ctx, scope.ContextID, nil
}

func nmsImportMCPReadError(err error) error {
	switch {
	case errors.Is(err, nmsimport.ErrPlanUnavailable):
		return apierror.NotFound("import plan not found in this routing context")
	case errors.Is(err, nmsimport.ErrInvalidPage):
		return apierror.BadRequest("invalid import page")
	case errors.Is(err, nmsimport.ErrInvalidReview):
		return apierror.BadRequest("invalid poll target selection")
	case errors.Is(err, nmsimport.ErrReviewStale):
		return apierror.Conflict("reviewed destination changed")
	case errors.Is(err, nmsimport.ErrSourceDrift):
		return apierror.Conflict("reviewed source changed")
	case errors.Is(err, nmsimport.ErrSourceUnavailable):
		return apierror.Unavailable("configured source is unavailable")
	default:
		return err
	}
}

func nmsImportCursor(cursor *int64) int64 {
	if cursor == nil {
		return -1
	}
	return *cursor
}

func nmsImportLimit(limit int) int {
	if limit == 0 {
		return 50
	}
	return limit
}

func (b mcpNMSImportBackend) NMSImportRows(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportRowsInput) (mcp.NMSImportRowsResult, error) {
	ctx, contextID, err := b.readScope(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NMSImportRowsResult{}, err
	}
	page, err := nmsimport.NewCaptureStore(b.pool, nil).ListSealedRows(ctx, contextID,
		input.PlanID, nmsImportCursor(input.Cursor), nmsImportLimit(input.Limit))
	if err != nil {
		return mcp.NMSImportRowsResult{}, nmsImportMCPReadError(err)
	}
	out := mcp.NMSImportRowsResult{ContextID: page.ContextID, PlanID: page.PlanID,
		SourceID:     page.SourceID,
		SnapshotHash: page.SnapshotHash, RowCount: page.RowCount,
		NextCursor: page.NextCursor, Items: make([]mcp.NMSImportRowResult, 0, len(page.Items))}
	for _, item := range page.Items {
		out.Items = append(out.Items, mcp.NMSImportRowResult{
			RowNumber: item.Number, Kind: item.Kind, ExternalID: item.ExternalID,
			Label: item.Label, Address: item.Address, Hostname: item.Hostname,
			ParentID: item.ParentID, LocationID: item.LocationID,
			LocationLabel: item.LocationLabel, GroupIDs: item.GroupIDs,
			PollSeconds: item.PollSeconds, Severity: item.Severity,
			UnmappedCodes: item.UnmappedCodes, Action: item.Action,
			TargetID: item.TargetID, Reviewed: item.Reviewed,
			State: item.State, AppliedAt: item.AppliedAt,
			BoundEntityID: item.BoundEntityID, BindingPlanID: item.BindingPlanID})
	}
	return out, nil
}

func (b mcpNMSImportBackend) NMSImportDryRun(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportDryRunInput) (mcp.NMSImportDryRunResult, error) {
	ctx, contextID, err := b.readScope(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NMSImportDryRunResult{}, err
	}
	page, err := nmsimport.NewCaptureStore(b.pool, nil).ListReviewDiff(ctx, contextID,
		input.PlanID, input.ReviewHash, nmsImportCursor(input.Cursor),
		nmsImportLimit(input.Limit))
	if err != nil {
		return mcp.NMSImportDryRunResult{}, nmsImportMCPReadError(err)
	}
	out := mcp.NMSImportDryRunResult{ContextID: page.ContextID, PlanID: page.PlanID,
		SnapshotHash: page.SnapshotHash, ReviewHash: page.ReviewHash,
		RowCount: page.RowCount, NextCursor: page.NextCursor,
		Items: make([]mcp.NMSImportDiffItemResult, 0, len(page.Items))}
	for _, item := range page.Items {
		out.Items = append(out.Items, mcp.NMSImportDiffItemResult{
			RowNumber: item.RowNumber, Kind: item.Kind, ExternalID: item.ExternalID,
			Action: item.Action, TargetID: item.TargetID,
			CurrentLabel: item.CurrentLabel, ProposedLabel: item.ProposedLabel,
			CurrentPollSeconds:  item.CurrentPollSeconds,
			ProposedPollSeconds: item.ProposedPollSeconds,
			ChangedFields:       item.ChangedFields, UnmappedCodes: item.UnmappedCodes})
	}
	return out, nil
}

func (b mcpNMSImportBackend) NMSImportPollProposals(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportPollProposalsInput) (mcp.NMSImportPollProposalsResult, error) {
	ctx, contextID, err := b.readScope(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NMSImportPollProposalsResult{}, err
	}
	page, err := nmsimport.NewCaptureStore(b.pool, nil).ListPollProposals(ctx,
		contextID, input.SourceID, input.Cursor, nmsImportLimit(input.Limit))
	if err != nil {
		return mcp.NMSImportPollProposalsResult{}, nmsImportMCPReadError(err)
	}
	out := mcp.NMSImportPollProposalsResult{ContextID: page.ContextID,
		SourceID: page.SourceID, NextCursor: page.NextCursor,
		Items: make([]mcp.NMSImportPollProposalResult, 0, len(page.Items))}
	for _, item := range page.Items {
		out.Items = append(out.Items, mcp.NMSImportPollProposalResult{
			ItemID: item.ItemID, HostID: item.HostID,
			PollSeconds: item.PollSeconds, PlanID: item.PlanID,
			Revision: item.Revision, AppliedAt: item.AppliedAt})
	}
	return out, nil
}

func (b mcpNMSImportBackend) NMSImportPollTarget(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportPollTargetInput) (mcp.NMSImportPollTargetResult, error) {
	ctx, contextID, err := b.readScope(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NMSImportPollTargetResult{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p,
		entity.Scope{TenantID: p.TenantID, ContextID: contextID},
		ai.PermEntitiesRead); err != nil {
		return mcp.NMSImportPollTargetResult{}, err
	}
	preview, err := nmsimport.NewCaptureStore(b.pool, nil).PreviewPollTarget(ctx,
		contextID, input.SourceID, input.ItemID, input.AgentID,
		input.TargetAddress)
	if err != nil {
		return mcp.NMSImportPollTargetResult{}, nmsImportMCPReadError(err)
	}
	return mcp.NMSImportPollTargetResult{
		TenantID: preview.TenantID, ContextID: preview.ContextID,
		SourceID: preview.SourceID, ItemID: preview.ItemID, HostID: preview.HostID,
		EntityID: preview.EntityID, AgentID: preview.AgentID,
		TargetAddress: preview.TargetAddress, PollSeconds: preview.PollSeconds,
		PlanID: preview.PlanID, Revision: preview.Revision,
	}, nil
}

func (b mcpNMSImportBackend) NMSImportAlertTarget(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportAlertTargetInput) (mcp.NMSImportAlertTargetResult, error) {
	ctx, contextID, err := b.readScope(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NMSImportAlertTargetResult{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p,
		entity.Scope{TenantID: p.TenantID, ContextID: contextID},
		ai.PermEntitiesRead); err != nil {
		return mcp.NMSImportAlertTargetResult{}, err
	}
	preview, err := nmsimport.NewCaptureStore(b.pool, nil).PreviewLibreNMSAlertTarget(ctx,
		contextID, input.SourceID, input.RuleID, input.AgentID, input.TargetAddress)
	if err != nil {
		return mcp.NMSImportAlertTargetResult{}, nmsImportMCPReadError(err)
	}
	return mcp.NMSImportAlertTargetResult{
		TenantID: preview.TenantID, ContextID: preview.ContextID,
		SourceID: preview.SourceID, RuleID: preview.RuleID,
		DeviceID: preview.DeviceID, EntityID: preview.EntityID,
		AgentID: preview.AgentID, TargetAddress: preview.TargetAddress,
		PlanID: preview.PlanID, SnapshotHash: preview.SnapshotHash,
		Name: preview.Name, Severity: preview.Severity,
		RuleKind: preview.RuleKind, Enabled: preview.Enabled,
	}, nil
}

func (b mcpNMSImportBackend) NMSImportAlertApply(ctx context.Context, p *auth.Principal,
	input mcp.NMSImportAlertApplyInput) (mcp.NMSImportAlertApplyResult, error) {
	ctx, contextID, err := b.scope(ctx, p, input.ContextID, permNMSImportWrite)
	if err != nil {
		return mcp.NMSImportAlertApplyResult{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	scope := entity.Scope{TenantID: p.TenantID, ContextID: contextID}
	for _, permission := range []string{ai.PermEntitiesRead, permAlertWrite} {
		if err := checker.requireEntityContext(ctx, p, scope, permission); err != nil {
			return mcp.NMSImportAlertApplyResult{}, err
		}
	}
	policy := nmsimport.LibreNMSFetchPolicy{}
	if b.owner != nil {
		policy = b.owner.nmsImportAlertFetchPolicy()
	}
	capturer := nmsimport.NewCaptureStore(b.pool,
		func(ctx context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
			_, err := audit.TenantAppend(ctx, sc, p.UserID, action, target, data)
			return err
		})
	result, err := capturer.ApplyLibreNMSAlertTarget(ctx, contextID,
		input.SourceID, input.RuleID, input.AgentID, input.TargetAddress,
		input.PlanID, input.SnapshotHash, input.EntityID, policy)
	if err != nil {
		return mcp.NMSImportAlertApplyResult{}, nmsImportMCPReadError(err)
	}
	return mcp.NMSImportAlertApplyResult{
		AlertRuleID: result.AlertRuleID, Created: result.Created}, nil
}
