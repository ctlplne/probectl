// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ResolveAddresses makes a bounded, single-transaction current join for a
// path's responder IPs. It uses the same active assignment, canonical anchor,
// tenant/context and certificate filters as ResolveAlias. Every input receives
// an explicit resolved, conflict or unresolved result.
func (s *EntityRegistry) ResolveAddresses(ctx context.Context, raw entity.Scope, addresses []string) (map[string]entity.Resolution, error) {
	want, err := s.scope(ctx, raw)
	if err != nil {
		return nil, err
	}
	if len(addresses) > 640 {
		return nil, entity.ErrInvalidPage
	}
	unique := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		key, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: address}).Normalize()
		if err != nil {
			return nil, err
		}
		if !seen[key.Value] {
			seen[key.Value] = true
			unique = append(unique, key.Value)
		}
	}
	claims := make(map[string][]entity.Claim, len(unique))
	if len(unique) > 0 {
		err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			// Bind evidence to one requested address before metadata joins. The
			// barrier retains that point lookup under incomplete tenant statistics;
			// it removes no candidates. Replan for this invocation's array length.
			rows, err := sc.Q.Query(ctx, `
			SELECT keys.alias_value, e.id::text, e.projected_entity_id::text, e.projected_kind,
			       e.source, e.source_ref, e.agent_id, e.source_kind,
			       e.configured_ref, e.observed_at,
			       COALESCE(e.support_evidence_id::text,'')
				  FROM unnest($3::text[]) AS keys(alias_value)
				  JOIN LATERAL (
				      SELECT DISTINCT ON (resolved_node.id) item.*,
				             resolved_node.id AS projected_entity_id,resolved_node.kind AS projected_kind
				        FROM (
				          SELECT * FROM entity_evidence
				           WHERE tenant_id=$1 AND context_id=$2
				             AND alias_kind='address' AND alias_value=keys.alias_value
				             AND observed_at<=statement_timestamp()
				             AND (expires_at IS NULL OR expires_at>statement_timestamp())
				          OFFSET 0
				        ) item
				        JOIN entities node ON
				             node.tenant_id=$1 AND node.context_id=$2 AND node.id=item.entity_id
				        JOIN entities resolved_node ON
				             resolved_node.tenant_id=$1 AND resolved_node.context_id=$2
				             AND resolved_node.id=COALESCE(node.parent_entity_id,item.entity_id)
				        JOIN entity_source_contexts m ON
				             m.tenant_id=$1 AND m.context_id=$2
				             AND (m.agent_id,m.source_kind,m.source_ref)=
				             (item.agent_id,item.source_kind,item.configured_ref)
		         AND ((item.support_evidence_id IS NULL AND
		               (m.anchor_entity_id=item.entity_id OR EXISTS (
			              SELECT 1 FROM entities child
			               WHERE (child.tenant_id,child.context_id,child.id)=
			                     (item.tenant_id,item.context_id,item.entity_id)
		                 AND child.parent_entity_id=m.anchor_entity_id)))
		              OR (m.anchor_entity_id IS NULL AND `+currentInferredSupportSQL("item")+`))
				        JOIN entity_agent_contexts a ON
				             a.tenant_id=$1 AND a.context_id=$2 AND a.agent_id=m.agent_id
				       WHERE m.assigned_at <= statement_timestamp()
				         AND m.assigned_at <= item.observed_at
				         AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
				         AND a.assigned_at <= statement_timestamp()
				         AND a.assigned_at <= item.observed_at
				         AND (a.expires_at IS NULL OR a.expires_at > statement_timestamp())
				         AND NOT EXISTS (SELECT 1 FROM agent_identities i
				              WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
				                AND i.revoked_at IS NOT NULL
				                AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
			         AND EXISTS (
			              SELECT 1 FROM agent_identities sender
			               WHERE sender.tenant_id=item.tenant_id
			                 AND sender.agent_id=item.agent_id
			                 AND sender.serial=item.sender_serial
			                 AND sender.spiffe_id='spiffe://probectl/tenant/' || item.tenant_id::text || '/entity/' || item.agent_id
			                 AND sender.revoked_at IS NULL
			                 AND sender.issued_at <= item.observed_at
			                 AND sender.not_after > statement_timestamp())
				         AND (item.source_kind <> 'bmp_peer' OR EXISTS (
				              SELECT 1 FROM agent_identities origin
				               WHERE origin.tenant_id=item.tenant_id
				                 AND origin.agent_id=item.configured_ref
				                 AND origin.serial=item.origin_serial
			                 AND origin.spiffe_id='spiffe://probectl/tenant/' || item.tenant_id::text || '/bmp/' || item.configured_ref
				                 AND origin.revoked_at IS NULL
			                 AND origin.issued_at <= item.observed_at
				                 AND origin.not_after > statement_timestamp()))
				       ORDER BY resolved_node.id, item.observed_at DESC, item.id
				       LIMIT 4
				  ) e ON true
				 ORDER BY keys.alias_value,e.projected_entity_id`, pgx.QueryExecModeDescribeExec, want.TenantID, want.ContextID, unique)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var address, kind, sourceKind string
				var claim entity.Claim
				claim.Scope = want
				if err := rows.Scan(&address, &claim.EvidenceID, &claim.EntityID,
					&kind, &claim.Source, &claim.SourceRef, &claim.SourceKey.AgentID,
					&sourceKind, &claim.SourceKey.SourceRef, &claim.ObservedAt,
					&claim.SupportEvidenceID); err != nil {
					return err
				}
				claim.Alias = entity.AliasKey{Kind: entity.AddressAlias, Value: address}
				claim.EntityKind = entity.Kind(kind)
				claim.SourceKey.Kind = entity.SourceKind(sourceKind)
				claims[address] = append(claims[address], claim)
			}
			return rows.Err()
		})
		if err != nil {
			return nil, err
		}
	}
	result := make(map[string]entity.Resolution, len(unique))
	for _, address := range unique {
		list := claims[address]
		more := len(list) > 3
		if more {
			list = list[:3]
		}
		resolved, err := entity.Resolve(want,
			entity.AliasKey{Kind: entity.AddressAlias, Value: address}, list)
		if err != nil {
			return nil, err
		}
		resolved.MoreCandidates = more
		result[address] = resolved
	}
	return result, nil
}
