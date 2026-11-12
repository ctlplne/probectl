// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Reuse the existing erasure epoch and lock order before issued identities or
// source rows. An erasure either waits for this transaction or its new cutoff
// refuses every earlier observation, even when its UUID row was deleted.
func entityEvidenceLifecycleScope(ctx context.Context, sc tenancy.Scope) (bool, time.Time, error) {
	if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
		return false, time.Time{}, err
	}
	if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
		return false, time.Time{}, err
	}
	var invalidating bool
	var cutoff *time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT invalidating OR observation_erasing,NULLIF(observation_not_before,'-infinity'::timestamptz)
		FROM flow_snapshot_epochs WHERE tenant_id=$1 FOR SHARE`, sc.Tenant.String()).Scan(&invalidating, &cutoff); err != nil {
		return false, time.Time{}, err
	}
	if cutoff == nil {
		return invalidating, time.Time{}, nil
	}
	return invalidating, *cutoff, nil
}
