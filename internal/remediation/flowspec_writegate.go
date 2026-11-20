// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"

	"github.com/ctlplne/probectl/internal/license"
)

func (g writeGatedService) PreviewFlowSpec(ctx context.Context, tenant string, input FlowSpecPreviewInput, check func(context.Context) error) (FlowSpecPreview, error) {
	service, ok := g.delegate.(FlowSpecPreviewer)
	if !ok {
		return FlowSpecPreview{}, Error{Code: "not_found", Message: "traffic review is unavailable"}
	}
	return service.PreviewFlowSpec(ctx, tenant, input, check)
}

func (g writeGatedService) ProposeFlowSpec(ctx context.Context, tenant, actor string, input FlowSpecProposalInput, check func(context.Context) error) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(FlowSpecReviews)
	if !ok {
		return Proposal{}, Error{Code: "not_found", Message: "traffic review is unavailable"}
	}
	return service.ProposeFlowSpec(ctx, tenant, actor, input, check)
}

func (g writeGatedService) GetFlowSpecReview(ctx context.Context, tenant, id string, check func(context.Context) error) (FlowSpecReview, error) {
	service, ok := g.delegate.(FlowSpecReviews)
	if !ok {
		return FlowSpecReview{}, Error{Code: "not_found", Message: "traffic review is unavailable"}
	}
	return service.GetFlowSpecReview(ctx, tenant, id, check)
}

func (g writeGatedService) ApproveFlowSpec(ctx context.Context, tenant, actor, id, fingerprint, note string, check func(context.Context) error) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(FlowSpecReviews)
	if !ok {
		return Proposal{}, Error{Code: "not_found", Message: "traffic review is unavailable"}
	}
	return service.ApproveFlowSpec(ctx, tenant, actor, id, fingerprint, note, check)
}
