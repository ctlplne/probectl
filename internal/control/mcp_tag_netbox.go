// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/entity"
)

type mcpNetBoxTagBackend struct {
	mcpTagBackend
	source *cmdb.Resolver
}

func (b mcpNetBoxTagBackend) NetBoxTagPreview(ctx context.Context, p *auth.Principal, input mcp.NetBoxTagPreviewInput) (mcp.NetBoxTagPreviewResult, error) {
	ctx, contextID, err := b.tagContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	local := netBoxTagPreviewRequest{TagID: input.TagID, TargetKind: input.TargetKind, TargetID: input.TargetID,
		ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef, SourceID: input.SourceID, Field: input.Field}
	permission, err := tagSubjectReadPermission(local.reference().Kind)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	for _, grant := range []string{permCMDBRead, permission} {
		if err := checker.requireEntityContext(ctx, p, entity.Scope{TenantID: p.TenantID, ContextID: contextID}, grant); err != nil {
			return mcp.NetBoxTagPreviewResult{}, err
		}
	}
	if input.Field != "role" && input.Field != "site" {
		return mcp.NetBoxTagPreviewResult{}, apierror.BadRequest("NetBox tag field must be role or site")
	}
	if b.source == nil {
		return mcp.NetBoxTagPreviewResult{}, apierror.Unavailable("NetBox tag source is unavailable")
	}
	ctx, budget, done, err := beginNetBoxImport(ctx, b.flowStore, b.fairnessGate)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	defer done()
	target, facts, err := readNetBoxTagTarget(ctx, b.pool, contextID, input.TagID, local.reference(), budget.MemoryBytes/4)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, tagAssignmentAPIError(err)
	}
	selected, err := b.source.PreviewNetBoxSubjectTag(ctx, sourceTagFacts(facts), input.Field, input.SourceID)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, netBoxTagPreviewError(err)
	}
	candidate := selected.Candidate()
	result := mcp.NetBoxTagPreviewResult{ContextID: contextID, TagID: target.TagID, TagKey: target.TagKey, TagRevision: target.TagRevision,
		TargetKind: target.TargetKind, TargetID: target.TargetID,
		NetBoxTenantID: candidate.NetBoxTenantID, LookupCIID: candidate.LookupCIID, CIID: candidate.CIID, Name: candidate.Name,
		Field: candidate.Field, Value: candidate.Value, SourceRef: candidate.SourceRef}
	if target.TargetKind == "exporter" {
		result.TargetID = ""
	}
	if err := netBoxImportResponseBudget(result, budget); err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	return result, nil
}
