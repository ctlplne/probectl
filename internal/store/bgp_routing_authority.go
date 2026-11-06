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

var ErrBGPRoutingSourceUnavailable = errors.New("current routing source authority is unavailable")

// BGPRouting uses an existing tenant transaction. It never derives a tenant or
// canonical router from a packet, peer address, ASN, or retained view row.
type BGPRouting struct{}

// BGPRoutingSource must come from the authenticated sender/origin transport.
// This storage check is additional to certificate/signature verification.
type BGPRoutingSource struct {
	entity.Scope
	RouterID, CollectorAgentID, SourceRef string
	SenderSerial, OriginSerial            string
	ObservedAt                            time.Time
	// Filled only by storage-owned selector resolution. Existing evidence
	// planes keep their original single-context assignment and credentials.
	routingSelection *routingSourceSelection
}

// BGPRoutingSourceAuthority describes this transaction only, not a reusable
// grant. Publication and every later lookup must recheck current authority.
type BGPRoutingSourceAuthority struct {
	AsOf, ValidUntil time.Time
}

func validateBGPRoutingSource(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, present := tenancy.FromContext(ctx)
	if !present || tenant != sc.Tenant || tenant.String() != source.TenantID {
		return entity.ErrScopeMismatch
	}
	normalized, err := source.Normalize()
	if err != nil || normalized != source.Scope {
		return entity.ErrInvalidScope
	}
	router, err := validRegistryUUID(source.RouterID)
	if err != nil || router != source.RouterID {
		return entity.ErrInvalidScope
	}
	for _, value := range []string{source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial} {
		if value == "" || strings.TrimSpace(value) != value {
			return entity.ErrInvalidClaim
		}
	}
	if source.ObservedAt.IsZero() {
		return entity.ErrInvalidClaim
	}
	return nil
}

// The existing service path checks tenant lifecycle and actor grants. This
// repository checks tenant-owned source authority without acquiring access to
// the provider tenant registry, matching current entity-evidence readers.
//
// sourceAuthorityInScope binds the exact tenant, context, explicit origin
// router, collector, both credential purposes/serials and assignment epochs.
// Rebinding cannot revive an observation older than the new assignment. FORCE
// RLS remains the outer boundary even if a query predicate is accidentally lost.
func (BGPRouting) sourceAuthorityInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource) (BGPRoutingSourceAuthority, error) {
	return routingSourceAuthority(ctx, sc, source, false)
}

// sourceAuthorityForWriteInScope holds the exact credential, assignment,
// source and router rows until commit. A concurrent change must precede the
// write or wait for it; an obsolete REPEATABLE READ snapshot fails rather
// than acknowledging credentials changed since that snapshot was taken.
func (BGPRouting) sourceAuthorityForWriteInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource) (BGPRoutingSourceAuthority, error) {
	return routingSourceAuthority(ctx, sc, source, true)
}

func routingSourceAuthority(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, lock bool) (BGPRoutingSourceAuthority, error) {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return BGPRoutingSourceAuthority{}, err
	}
	if source.routingSelection != nil {
		return boundRoutingSourceAuthority(ctx, sc, source, lock)
	}
	return routingCredentialAuthority(ctx, sc, source, lock, "")
}

func routingCredentialAuthority(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, lock bool, epoch string) (BGPRoutingSourceAuthority, error) {
	if sc.Q == nil {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	var result BGPRoutingSourceAuthority
	query := `SELECT transaction_timestamp(),
 LEAST(source.expires_at,assignment.expires_at,sender.not_after,origin.not_after)
 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON
 (assignment.tenant_id,assignment.agent_id,assignment.context_id)=
 (source.tenant_id,source.agent_id,source.context_id)
 JOIN entities router ON
 (router.tenant_id,router.context_id,router.id)=(source.tenant_id,source.context_id,source.anchor_entity_id)
 AND router.kind='device'
 JOIN agent_identities sender ON
 (sender.tenant_id,sender.agent_id,sender.serial)=(source.tenant_id,source.agent_id,$5)
 AND sender.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/entity/' || source.agent_id
 JOIN agent_identities origin ON
 (origin.tenant_id,origin.agent_id,origin.serial)=(source.tenant_id,source.source_ref,$6)
 AND origin.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/bmp/' || source.source_ref
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.anchor_entity_id=$3
 AND source.agent_id=$4 AND source.source_kind='bmp_peer' AND source.source_ref=$7
 AND source.routing_epoch IS NULL
 AND $8::timestamptz<=transaction_timestamp()
 AND source.assigned_at<=$8 AND assignment.assigned_at<=$8
 AND (source.expires_at IS NULL OR source.expires_at>transaction_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>transaction_timestamp())
 AND sender.issued_at<=$8 AND sender.not_after>transaction_timestamp() AND sender.revoked_at IS NULL
 AND origin.issued_at<=$8 AND origin.not_after>transaction_timestamp() AND origin.revoked_at IS NULL
 AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
 WHERE revoked.tenant_id=source.tenant_id AND revoked.agent_id=source.agent_id
	AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')`
	args := []any{source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID,
		source.SenderSerial, source.OriginSerial, source.SourceRef, source.ObservedAt}
	if epoch != "" {
		query = strings.Replace(query, "source.routing_epoch IS NULL", "source.routing_epoch=$9", 1)
		args = append(args, epoch)
	}
	if lock {
		query += ` FOR SHARE OF sender,origin,assignment,source,router`
	}
	err := sc.Q.QueryRow(ctx, query, args...).Scan(&result.AsOf, &result.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return BGPRoutingSourceAuthority{}, err
	}
	if lock {
		// A lock wait can outlive a certificate or assignment. Transaction
		// start time is insufficient after waiting for another writer.
		if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&result.AsOf); err != nil {
			return BGPRoutingSourceAuthority{}, err
		}
	}
	if !result.ValidUntil.After(result.AsOf) {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	return result, nil
}
