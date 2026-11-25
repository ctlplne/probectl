// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/license"
)

var errRoutingTransferReviewUnavailable = Error{Code: "not_found", Message: "routing transfer review is unavailable"}

func (g writeGatedService) ProposeRoutingTransfer(ctx context.Context, tenant, actor string, selection json.RawMessage,
	fingerprint, maxMoved string, prepare RoutingTransferReviewPrepare) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(RoutingTransferReviewService)
	if !ok {
		return Proposal{}, errRoutingTransferReviewUnavailable
	}
	return service.ProposeRoutingTransfer(ctx, tenant, actor, selection, fingerprint, maxMoved, prepare)
}

func (g writeGatedService) GetRoutingTransfer(ctx context.Context, tenant, id string, prepare RoutingTransferReviewPrepare) (RoutingTransferReview, error) {
	service, ok := g.delegate.(RoutingTransferReviewService)
	if !ok {
		return RoutingTransferReview{}, errRoutingTransferReviewUnavailable
	}
	return service.GetRoutingTransfer(ctx, tenant, id, prepare)
}

func (g writeGatedService) ApproveRoutingTransfer(ctx context.Context, tenant, actor, id, fingerprint, note string,
	prepare RoutingTransferReviewPrepare) (Proposal, error) {
	if !g.writes.Enabled() {
		return Proposal{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(RoutingTransferReviewService)
	if !ok {
		return Proposal{}, errRoutingTransferReviewUnavailable
	}
	return service.ApproveRoutingTransfer(ctx, tenant, actor, id, fingerprint, note, prepare)
}

func (g writeGatedService) GetRoutingTransferRollback(ctx context.Context, tenant, id string,
	authorize RoutingTransferRollbackAuthorizer) (RoutingTransferRollback, error) {
	service, ok := g.delegate.(RoutingTransferRollbackService)
	if !ok {
		return RoutingTransferRollback{}, errRoutingTransferReviewUnavailable
	}
	return service.GetRoutingTransferRollback(ctx, tenant, id, authorize)
}

func (g writeGatedService) RequestRoutingTransferWithdrawal(ctx context.Context, tenant, actor, id, fingerprint string,
	authorize RoutingTransferRollbackAuthorizer) (RoutingTransferRollback, error) {
	if !g.writes.Enabled() {
		return RoutingTransferRollback{}, license.ErrReadOnly
	}
	service, ok := g.delegate.(RoutingTransferRollbackService)
	if !ok {
		return RoutingTransferRollback{}, errRoutingTransferReviewUnavailable
	}
	return service.RequestRoutingTransferWithdrawal(ctx, tenant, actor, id, fingerprint, authorize)
}
