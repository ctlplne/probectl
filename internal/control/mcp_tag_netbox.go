// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mcpNetBoxTagBackend struct {
	mcpTagBackend
	source *cmdb.Resolver
}

func (b mcpNetBoxTagBackend) NetBoxTagPreview(ctx context.Context, p *auth.Principal,
	input mcp.NetBoxTagPreviewInput) (mcp.NetBoxTagPreviewResult, error) {
	ctx, contextID, err := b.tagContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p, entity.Scope{TenantID: p.TenantID, ContextID: contextID}, permCMDBRead); err != nil {
		return mcp.NetBoxTagPreviewResult{}, err
	}
	if input.Field != "role" && input.Field != "site" {
		return mcp.NetBoxTagPreviewResult{}, apierror.BadRequest("NetBox tag field must be role or site")
	}
	var target store.NetBoxTagTarget
	err = tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		target, err = (store.TagAssignments{}).NetBoxExporterTarget(ctx, sc, contextID,
			input.TagID, input.ExporterAgentID, input.ExporterSourceRef)
		return err
	})
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, tagAssignmentAPIError(err)
	}
	if b.source == nil {
		return mcp.NetBoxTagPreviewResult{}, apierror.Unavailable("NetBox tag source is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	candidate, err := b.source.PreviewNetBoxTag(ctx, target.ExporterSourceRef, input.Field)
	if err != nil {
		return mcp.NetBoxTagPreviewResult{}, netBoxTagPreviewError(err)
	}
	return mcp.NetBoxTagPreviewResult{ContextID: contextID, TagID: target.TagID,
		TagKey: target.TagKey, TagRevision: target.TagRevision,
		NetBoxTenantID: candidate.NetBoxTenantID, LookupCIID: candidate.LookupCIID,
		CIID: candidate.CIID, Name: candidate.Name, Field: candidate.Field,
		Value: candidate.Value, SourceRef: candidate.SourceRef}, nil
}
