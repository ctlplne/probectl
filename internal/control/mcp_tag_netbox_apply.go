// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
)

type mcpNetBoxTagApplyBackend struct{ server *Server }

func (b mcpNetBoxTagApplyBackend) NetBoxTagApply(ctx context.Context, p *auth.Principal,
	input mcp.NetBoxTagApplyInput) (mcp.NetBoxTagApplyResult, error) {
	if b.server == nil || p == nil || p.TenantID == "" || p.UserID == "" {
		return mcp.NetBoxTagApplyResult{}, apierror.Forbidden("an authenticated tenant user is required")
	}
	targetID, err := tags.ExporterTargetID(input.ExporterAgentID, input.ExporterSourceRef)
	if err != nil {
		return mcp.NetBoxTagApplyResult{}, tagAssignmentAPIError(err)
	}
	observed := input.Preview
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, p), http.MethodPost,
		"/v1/entity-contexts/"+observed.ContextID+"/tag-imports/netbox/apply", nil)
	if err != nil {
		return mcp.NetBoxTagApplyResult{}, apierror.BadRequest("invalid NetBox tag context")
	}
	request.SetPathValue("context_id", observed.ContextID)
	record, err := b.server.applyReviewedNetBoxTag(request, netBoxTagApplyRequest{
		Confirmed: input.Confirmed, Preview: netBoxTagPreview{
			Target: store.NetBoxTagTarget{ContextID: observed.ContextID,
				TagID: observed.TagID, TagKey: observed.TagKey, TagRevision: observed.TagRevision,
				TargetKind: "exporter", TargetID: targetID,
				ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef},
			Candidate: cmdb.NetBoxTagCandidate{NetBoxTenantID: observed.NetBoxTenantID,
				LookupCIID: observed.LookupCIID, CIID: observed.CIID, Name: observed.Name,
				Field: observed.Field, Value: observed.Value, SourceRef: observed.SourceRef}}})
	if err != nil {
		return mcp.NetBoxTagApplyResult{}, err
	}
	return mcp.NetBoxTagApplyResult{AssignmentID: record.ID, ContextID: record.ContextID,
		TagID: record.TagID, Value: record.Value, SourceRef: record.SourceRef,
		ReviewedAt: record.ReviewedAt.UTC().Format(time.RFC3339Nano)}, nil
}
