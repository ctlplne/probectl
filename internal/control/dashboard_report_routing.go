// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) revalidateReportRoutingScope(ctx context.Context, sc tenancy.Scope, principal *auth.Principal, capture *reportFlowCapture) error {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	for _, input := range capture.Inputs {
		if !input.RoutingSource {
			if input.Routing != nil {
				return apierror.Forbidden("report routing receipt has no source lineage")
			}
			continue
		}
		if !capture.ContextSources || !capture.ContextsCaptured || !reportRoutingRequirementsComplete(input) {
			return apierror.Forbidden("report routing source requirements are incomplete")
		}
		reads, err := decodeFlowRoutingValidity(ctx, capture.TenantID, input.Routing, budget.MemoryBytes/4)
		if err != nil {
			return flowRoutingQueryError(err)
		}
		current, err := s.loadFlowRoutingSnapshotInScope(ctx, sc, principal, budget, func(context.Context) ([]flowstore.RoutingCaptureRead, error) { return reads, nil }, true)
		if err != nil {
			return flowRoutingQueryError(err)
		}
		if current.digest != input.Routing.Digest || current.inputDigest != input.Routing.InputDigest {
			return apierror.Forbidden("report routing source authority changed")
		}
	}
	return ctx.Err()
}
