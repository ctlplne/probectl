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
// and reports whether THIS call won the claim.
func (ComplianceAlerted) Claim(ctx context.Context, s tenancy.Scope, policy, rule string) (bool, error) {
	tag, err := s.Q.Exec(ctx, `
		INSERT INTO compliance_alerted (tenant_id, policy, rule)
		VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2)
		ON CONFLICT (tenant_id, policy, rule) DO NOTHING`, policy, rule)
	if err != nil {
		return false, fmt.Errorf("compliance alerted: claim: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Release forgets a claim so the next observed violation of the pair is
// exported again (an operator re-arming a rule after remediation).
func (ComplianceAlerted) Release(ctx context.Context, s tenancy.Scope, policy, rule string) error {
	if _, err := s.Q.Exec(ctx, `DELETE FROM compliance_alerted WHERE policy = $1 AND rule = $2`, policy, rule); err != nil {
		return fmt.Errorf("compliance alerted: release: %w", err)
	}
	return nil
}
