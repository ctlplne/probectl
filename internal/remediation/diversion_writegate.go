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

var errDiversionUnavailable = Error{Code: "not_found", Message: "local diversion preview is unavailable"}

func (g writeGatedService) PreviewDiversion(ctx context.Context, tenant string, input DiversionPreviewInput, check func(context.Context) error) (DiversionPreview, error) {
	service, ok := g.delegate.(DiversionReviews)
	if !ok {
		return DiversionPreview{}, errDiversionUnavailable
	}
	return service.PreviewDiversion(ctx, tenant, input, check)
}

func (g writeGatedService) ProposeDiversion(ctx context.Context, tenant, actor string, input DiversionProposalInput, check func(context.Context) error, publication RTBHImpactPublication) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(DiversionReviews)
	if !ok {
		return Proposal{}, errDiversionUnavailable
	}
	return service.ProposeDiversion(ctx, tenant, actor, input, check, publication)
}

func (g writeGatedService) GetDiversionReview(ctx context.Context, tenant, id string, check func(context.Context) error) (DiversionReview, error) {
	service, ok := g.delegate.(DiversionReviews)
	if !ok {
		return DiversionReview{}, errDiversionUnavailable
	}
	return service.GetDiversionReview(ctx, tenant, id, check)
}

func (g writeGatedService) ApproveDiversion(ctx context.Context, tenant, actor, id string, input DiversionApprovalInput, check func(context.Context) error, publication RTBHImpactPublication) (DiversionReceipt, error) {
	if !g.writes.Enabled() {
		return DiversionReceipt{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(DiversionReviews)
	if !ok {
		return DiversionReceipt{}, errDiversionUnavailable
	}
	return service.ApproveDiversion(ctx, tenant, actor, id, input, check, publication)
}
