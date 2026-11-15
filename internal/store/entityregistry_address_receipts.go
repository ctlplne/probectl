// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CheckCurrentAddressClaims rechecks the exact retained receipts in an already
// scoped resolution. A newer poll need not have the same receipt ID, but cannot
// make an expired, deleted, revoked or rebound original current again. Callers
// independently resolve today's complete candidate set to detect conflicts.
func (s *EntityRegistry) CheckCurrentAddressClaims(ctx context.Context, raw entity.Scope, claims []entity.Claim, memoryBytes int64) error {
	want, err := s.scope(ctx, raw)
	if err != nil {
		return err
	}
	if memoryBytes <= 0 || int64(len(claims)) > memoryBytes/8192 {
		return entity.ErrInvalidPage
	}
	ids := make([]string, 0, len(claims))
	expected := make(map[string]entity.Claim, len(claims))
	for _, claim := range claims {
		if claim.Scope != want || claim.Alias.Kind != entity.AddressAlias {
			return entity.ErrScopeMismatch
		}
		if _, err := entity.Resolve(want, claim.Alias, []entity.Claim{claim}); err != nil {
			return err
		}
		if previous, exists := expected[claim.EvidenceID]; exists {
			if !sameRetainedAddressClaim(previous, claim) {
				return ErrEntityRegistryUnavailable
			}
		} else {
			ids = append(ids, claim.EvidenceID)
			expected[claim.EvidenceID] = claim
		}
	}
	if len(ids) == 0 {
		return ctx.Err()
	}
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT e.id::text,resolved.id::text,resolved.kind,
 e.source,e.source_ref,e.agent_id,e.source_kind,e.configured_ref,e.observed_at,
 COALESCE(e.support_evidence_id::text,''),e.alias_value FROM entity_evidence e
 JOIN entities node ON (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id)
 JOIN entities resolved ON (resolved.tenant_id,resolved.context_id,resolved.id)=
 (node.tenant_id,node.context_id,COALESCE(node.parent_entity_id,e.entity_id))
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.alias_kind='address'
 AND e.id=ANY($3::uuid[]) AND `+currentEntityEvidenceSnapshotSQL(false), want.TenantID, want.ContextID, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			claim := entity.Claim{Scope: want, Alias: entity.AliasKey{Kind: entity.AddressAlias}}
			var kind, sourceKind string
			if err := rows.Scan(&claim.EvidenceID, &claim.EntityID, &kind, &claim.Source, &claim.SourceRef,
				&claim.SourceKey.AgentID, &sourceKind, &claim.SourceKey.SourceRef, &claim.ObservedAt,
				&claim.SupportEvidenceID, &claim.Alias.Value); err != nil {
				return err
			}
			claim.EntityKind, claim.SourceKey.Kind = entity.Kind(kind), entity.SourceKind(sourceKind)
			if !sameRetainedAddressClaim(expected[claim.EvidenceID], claim) {
				return ErrEntityRegistryUnavailable
			}
			count++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if count != len(ids) {
			return ErrEntityRegistryUnavailable
		}
		return ctx.Err()
	})
}

func sameRetainedAddressClaim(before, current entity.Claim) bool {
	if !before.ObservedAt.Equal(current.ObservedAt) {
		return false
	}
	current.ObservedAt = before.ObservedAt
	return before == current
}
