// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// CostBudgetAlerted is the cluster-wide once-only gate for a budget-breach
// signal (DPR-080): every control replica evaluates the same flow stream, so the
// first replica to Claim a (budget, month) pair files the incident signal and
// every other replica — and every replay after a rollout — stays quiet. Rows are
// tenant-scoped by FORCE RLS on probectl.tenant_id.
type CostBudgetAlerted struct{}

// Claim records that the tenant's budget breach for the month has been exported
// and reports whether THIS call won the claim.
func (CostBudgetAlerted) Claim(ctx context.Context, s tenancy.Scope, budgetKey, month string) (bool, error) {
	tag, err := s.Q.Exec(ctx, `
		INSERT INTO cost_budget_alerted (tenant_id, budget_key, month)
		VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2)
		ON CONFLICT (tenant_id, budget_key, month) DO NOTHING`, budgetKey, month)
	if err != nil {
		return false, fmt.Errorf("cost budget alerted: claim: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
