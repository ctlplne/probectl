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

// ComplianceAlerted is the cluster-wide once-only gate for a segmentation
// violation's side effects (DPR-073). Every control replica evaluates the same
// traffic (view groups), so the first replica to Claim a (policy, rule) pair
// exports the incident signal and SIEM event; every other replica — and every
// replay after a rollout — finds the row and stays quiet. Rows are tenant-scoped
// by FORCE RLS on probectl.tenant_id.
type ComplianceAlerted struct{}

// Claim records that the tenant's (policy, rule) violation has been exported
// for period and reports whether THIS call won the claim.
//
// The period is what makes the gate a de-duplicator rather than a mute button
// (DPR-110). Keyed by the pair alone, a violation's incident and SIEM event
// could fire exactly once for the life of the deployment: an operator who
// remediated and later saw the same traffic return was told nothing. Keyed by
// pair AND period, replicas and replays inside the window still collapse to one
// export, and the next window re-arms — the same shape the cost gate uses for
// budget breaches.
func (ComplianceAlerted) Claim(ctx context.Context, s tenancy.Scope, policy, rule, period string) (bool, error) {
	tag, err := s.Q.Exec(ctx, `
		INSERT INTO compliance_alerted (tenant_id, policy, rule, period)
		VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3)
		ON CONFLICT (tenant_id, policy, rule, period) DO NOTHING`, policy, rule, period)
	if err != nil {
		return false, fmt.Errorf("compliance alerted: claim: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
