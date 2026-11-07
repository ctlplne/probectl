// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPPublicRoutingSource comes from current authenticated collector transport,
// never a route payload. It has no router or origin credential. SourceRef is
// the operator's exact feed/format/collector assignment, not an anomaly prefix.
type BGPPublicRoutingSource struct {
	entity.Scope
	CollectorAgentID, SenderSerial, SourceRef string
	ObservedAt                                time.Time
}

func validatePublicRoutingSource(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || tenant.String() != source.TenantID {
		return entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := source.Normalize()
	if err != nil || normalized != source.Scope {
		return entity.ErrInvalidScope
	}
	key := entity.SourceKey{AgentID: source.CollectorAgentID, Kind: entity.PublicBGP, SourceRef: source.SourceRef}
	if normalized, err := key.Normalize(); err != nil || normalized != key || source.SenderSerial == "" ||
		strings.TrimSpace(source.SenderSerial) != source.SenderSerial || source.ObservedAt.IsZero() {
		return entity.ErrInvalidClaim
	}
	return nil
}

// publicSourceAuthorityInScope checks current tenant storage even for retained
// rows. FOR SHARE is additional protection for an existing fenced write
// transaction; callers must recheck after any later lock wait before publishing.
// Public ASN/collector names and bus tenant labels never replace this check.
func (BGPRouting) publicSourceAuthorityInScope(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, lock bool) (BGPRoutingSourceAuthority, error) {
	none := BGPRoutingSourceAuthority{}
	if err := validatePublicRoutingSource(ctx, sc, source); err != nil {
		return none, err
	}
	if sc.Q == nil {
		return none, ErrBGPRoutingSourceUnavailable
	}
	query := `SELECT transaction_timestamp(),LEAST(source.expires_at,assignment.expires_at,sender.not_after)
 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON
 (assignment.tenant_id,assignment.agent_id,assignment.context_id)=
 (source.tenant_id,source.agent_id,source.context_id)
 JOIN agent_identities sender ON
 (sender.tenant_id,sender.agent_id,sender.serial)=(source.tenant_id,source.agent_id,$5)
 AND sender.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/entity/' || source.agent_id
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.agent_id=$3
 AND source.source_kind='public_bgp' AND source.source_ref=$4 AND source.anchor_entity_id IS NULL
 AND source.routing_epoch IS NULL AND source.routing_bindings IS NULL AND source.routing_assigned_at IS NULL
 AND $6::timestamptz<=transaction_timestamp()
 AND source.assigned_at<=$6 AND assignment.assigned_at<=$6 AND sender.issued_at<=$6
 AND (source.expires_at IS NULL OR source.expires_at>transaction_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>transaction_timestamp())
 AND sender.not_after>transaction_timestamp() AND sender.revoked_at IS NULL
 AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
 WHERE revoked.tenant_id=source.tenant_id AND revoked.agent_id=source.agent_id
 AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')`
	if lock {
		query += ` FOR SHARE OF source,assignment,sender`
	}
	var result BGPRoutingSourceAuthority
	err := sc.Q.QueryRow(ctx, query, source.TenantID, source.ContextID, source.CollectorAgentID,
		source.SourceRef, source.SenderSerial, source.ObservedAt).Scan(&result.AsOf, &result.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return none, err
	}
	if lock {
		if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&result.AsOf); err != nil {
			return none, err
		}
	}
	if !result.ValidUntil.After(result.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	return result, nil
}
