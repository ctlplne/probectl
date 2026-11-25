// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CheckLockedRoutingPolicyArchiveExpiryInScope checks that the archive
// assignments still cover the approval deadline using the database clock.
// The caller holds the original archive and assignment locks from
// LockRoutingPolicyArchiveInScope. A shorter surviving lease requires review.
func CheckLockedRoutingPolicyArchiveExpiryInScope(ctx context.Context, sc tenancy.Scope, expected ConfigVersion, deadline time.Time) error {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || sc.Q == nil || tenant != sc.Tenant || tenant.String() != expected.TenantID || expected.Binding == nil {
		return entity.ErrScopeMismatch
	}
	if deadline.IsZero() {
		return ErrConfigBinding
	}
	binding := expected.Binding
	var covered bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM entity_source_contexts source
 JOIN entity_agent_contexts agent ON
 (agent.tenant_id,agent.context_id,agent.agent_id)=(source.tenant_id,source.context_id,source.agent_id)
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.anchor_entity_id=$3 AND source.agent_id=$4
 AND source.source_kind='device_target' AND source.source_ref=$5
 AND source.assigned_at=$6 AND agent.assigned_at=$7
 AND (source.expires_at IS NULL OR source.expires_at>=$8)
 AND (agent.expires_at IS NULL OR agent.expires_at>=$8)
 AND clock_timestamp()<$8
 )`, tenant.String(), binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef,
		binding.SourceAssignedAt, binding.AgentAssignedAt, deadline).Scan(&covered)
	if err != nil {
		return err
	}
	if !covered {
		return ErrConfigBinding
	}
	return ctx.Err()
}
