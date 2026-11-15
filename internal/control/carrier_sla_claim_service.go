// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// One admitted request owns the complete selected population, retained
// statements and every publication replay. A foreign or unavailable selection
// refuses the whole draft; no partial group is a successful result.
func (s *Server) prepareCarrierSLAClaim(op capacityAgreementOperation, input flow.CarrierSLAClaimRequest) (flow.CarrierSLAClaimDraft, func(context.Context) error, error) {
	none := flow.CarrierSLAClaimDraft{}
	if len(input.Selections) == 0 {
		return none, nil, apierror.Validation("explicit recorded agreement selections are required")
	}
	if int64(len(input.Selections)) > op.budget.MemoryBytes/4096 {
		return none, nil, store.ErrClientReportBudget
	}
	readBytes, readRows, memory := op.budget.ReadBytes, int64(op.budget.ReadRows), op.budget.MemoryBytes/2
	op.chargeRead = func(bytes, rows int64) error {
		if bytes < 0 || rows < 0 || bytes > readBytes || rows > readRows {
			return store.ErrClientReportBudget
		}
		readBytes -= bytes
		readRows -= rows
		return op.request.Context().Err()
	}
	op.chargeRetained = func(bytes int64) error {
		if bytes < 0 || bytes > memory/16 {
			return store.ErrClientReportBudget
		}
		memory -= bytes * 16
		return op.request.Context().Err()
	}
	statements := make([]flow.CarrierSLAStatement, 0, len(input.Selections))
	requirements := make([]carrierSLAClaimRequirement, 0, len(input.Selections))
	op.captureSLA = func(agreement flow.CapacityAgreement, sources []store.IncidentConfiguredTest) {
		requirements = append(requirements, carrierSLAClaimRequirement{agreement, sources})
	}
	checks := make([]func(context.Context) error, 0, len(input.Selections))
	for _, selection := range input.Selections {
		statement, check, err := s.calculateCarrierSLA(op, selection.AgreementID, flow.CarrierSLARequest{Version: selection.Version, At: selection.At})
		if err != nil {
			return none, nil, err
		}
		statements = append(statements, statement)
		checks = append(checks, check)
	}
	result, err := flow.GroupCarrierSLAClaims(op.request.Context(), statements, memory, op.budget.ReadBytes/4)
	if err != nil {
		return none, nil, err
	}
	publication := func(ctx context.Context) error {
		for _, check := range checks {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			for _, requirement := range requirements {
				if err := s.revalidateCarrierSLAClaimInScope(ctx, sc, op, requirement); err != nil {
					return err
				}
			}
			return ctx.Err()
		})
	}
	return result, publication, nil
}
