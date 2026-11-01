// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// An observation's address is informational, never a tenant/context key.
// Normalize has already checked the source-family provenance before this is
// called. BMP's router ID is not the peer address, so use its validated alias.
func inferredObservationAddress(claim entity.Observation) (string, error) {
	switch claim.Source.Kind {
	case entity.FlowExporter:
		return claim.Source.SourceRef, nil
	case entity.BMPPeer:
		if claim.Alias.Kind == entity.AddressAlias {
			return claim.Alias.Value, nil
		}
		if claim.Alias.Kind == entity.BMPPeerAlias {
			if index := strings.LastIndex(claim.Alias.Value, "/as"); index > 0 {
				return claim.Alias.Value[:index], nil
			}
		}
	}
	return "", entity.ErrInvalidClaim
}

// independentSNMPSupport finds one current, independently authenticated SNMP
// device for an unanchored flow/BMP address. The caller is already inside the
// authenticated tenant transaction. A second distinct device is a conflict;
// duplicate observations of the same device do not create one.
func independentSNMPSupport(ctx context.Context, sc tenancy.Scope, tenantID, contextID,
	address string, observedAt time.Time) (deviceID, supportID string, err error) {
	rows, err := sc.Q.Query(ctx, `
		SELECT DISTINCT ON (COALESCE(n.parent_entity_id,n.id))
		       COALESCE(n.parent_entity_id,n.id)::text, e.id::text
		  FROM entity_evidence e
		  JOIN entities n ON (n.tenant_id,n.context_id,n.id)=
		                     (e.tenant_id,e.context_id,e.entity_id)
		  JOIN entity_source_contexts m ON
		       (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
		       (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
		     AND m.anchor_entity_id=COALESCE(n.parent_entity_id,n.id)
		  JOIN entity_agent_contexts a ON
		       (a.tenant_id,a.agent_id,a.context_id)=
		       (m.tenant_id,m.agent_id,m.context_id)
		 WHERE e.tenant_id=$1 AND e.context_id=$2
		   AND e.source_kind='device_target' AND e.alias_kind='address'
		   AND e.alias_value=$3 AND n.kind IN ('device','interface')
		   AND e.observed_at<=$4 AND e.observed_at<=statement_timestamp()
		   AND (e.expires_at IS NULL OR e.expires_at>statement_timestamp())
		   AND m.assigned_at<=e.observed_at AND m.assigned_at<=statement_timestamp()
		   AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
		   AND a.assigned_at<=e.observed_at AND a.assigned_at<=statement_timestamp()
		   AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
		   AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
		       WHERE revoked.tenant_id=e.tenant_id AND revoked.agent_id=e.agent_id
		         AND revoked.revoked_at IS NOT NULL
		         AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		   AND EXISTS (SELECT 1 FROM agent_identities sender
		       WHERE sender.tenant_id=e.tenant_id AND sender.agent_id=e.agent_id
		         AND sender.serial=e.sender_serial
		         AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
		         AND sender.revoked_at IS NULL
		         AND sender.issued_at<=e.observed_at
		         AND sender.not_after>statement_timestamp())
		 ORDER BY COALESCE(n.parent_entity_id,n.id),e.observed_at DESC,e.id
		 LIMIT 2`, tenantID, contextID, address, observedAt)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var candidateDevice, candidateSupport string
		if err := rows.Scan(&candidateDevice, &candidateSupport); err != nil {
			return "", "", err
		}
		count++
		if count == 1 {
			deviceID, supportID = candidateDevice, candidateSupport
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if count != 1 {
		return "", "", nil
	}
	return deviceID, supportID, nil
}

// currentInferredSupportSQL is a storage-layer guard for a flow/BMP device
// inferred from an independent SNMP address observation. It is shared by the
// single-alias, batched-address and detail reads so no surface can revive an
// inferred join after its exact support expires, is rebound or conflicts. The
// only accepted aliases are static SQL identifiers in this package.
func currentInferredSupportSQL(evidenceAlias string) string {
	if evidenceAlias != "e" && evidenceAlias != "item" {
		panic("entity registry: unsupported evidence SQL alias")
	}
	return strings.ReplaceAll(inferredSupportPredicate, "@e@", evidenceAlias)
}

const inferredSupportPredicate = `
  @e@.support_evidence_id IS NOT NULL
  AND @e@.source_kind IN ('flow_exporter','bmp_peer')
  AND EXISTS (
    SELECT 1
      FROM entity_evidence support
      JOIN entities support_node ON
           (support_node.tenant_id,support_node.context_id,support_node.id)=
           (support.tenant_id,support.context_id,support.entity_id)
      JOIN entity_source_contexts support_source ON
           (support_source.tenant_id,support_source.context_id,
            support_source.agent_id,support_source.source_kind,support_source.source_ref)=
           (support.tenant_id,support.context_id,
            support.agent_id,support.source_kind,support.configured_ref)
         AND support_source.anchor_entity_id=COALESCE(support_node.parent_entity_id,support_node.id)
      JOIN entity_agent_contexts support_agent ON
           (support_agent.tenant_id,support_agent.agent_id,support_agent.context_id)=
           (support_source.tenant_id,support_source.agent_id,support_source.context_id)
     WHERE (support.tenant_id,support.context_id,support.id)=
           (@e@.tenant_id,@e@.context_id,@e@.support_evidence_id)
       AND support.source_kind='device_target'
       AND support.alias_kind='address'
       AND support_node.kind IN ('device','interface')
       AND COALESCE(support_node.parent_entity_id,support_node.id)=@e@.entity_id
       AND support.alias_value=CASE
           WHEN @e@.source_kind='flow_exporter' THEN @e@.configured_ref
           WHEN @e@.alias_kind='address' THEN @e@.alias_value
           ELSE split_part(@e@.alias_value,'/as',1) END
       AND support.observed_at<=@e@.observed_at
       AND support.observed_at<=statement_timestamp()
       AND (support.expires_at IS NULL OR support.expires_at>statement_timestamp())
       AND support_source.assigned_at<=support.observed_at
       AND support_source.assigned_at<=statement_timestamp()
       AND (support_source.expires_at IS NULL OR support_source.expires_at>statement_timestamp())
       AND support_agent.assigned_at<=support.observed_at
       AND support_agent.assigned_at<=statement_timestamp()
       AND (support_agent.expires_at IS NULL OR support_agent.expires_at>statement_timestamp())
       AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
           WHERE revoked.tenant_id=support.tenant_id AND revoked.agent_id=support.agent_id
             AND revoked.revoked_at IS NOT NULL
             AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
       AND EXISTS (SELECT 1 FROM agent_identities sender
           WHERE sender.tenant_id=support.tenant_id AND sender.agent_id=support.agent_id
             AND sender.serial=support.sender_serial
             AND sender.spiffe_id='spiffe://probectl/tenant/' || support.tenant_id::text || '/entity/' || support.agent_id
             AND sender.revoked_at IS NULL
             AND sender.issued_at<=support.observed_at
             AND sender.not_after>statement_timestamp())
       AND NOT EXISTS (
           SELECT 1
             FROM entity_evidence rival
             JOIN entities rival_node ON
                  (rival_node.tenant_id,rival_node.context_id,rival_node.id)=
                  (rival.tenant_id,rival.context_id,rival.entity_id)
             JOIN entity_source_contexts rival_source ON
                  (rival_source.tenant_id,rival_source.context_id,
                   rival_source.agent_id,rival_source.source_kind,rival_source.source_ref)=
                  (rival.tenant_id,rival.context_id,
                   rival.agent_id,rival.source_kind,rival.configured_ref)
                AND rival_source.anchor_entity_id=COALESCE(rival_node.parent_entity_id,rival_node.id)
             JOIN entity_agent_contexts rival_agent ON
                  (rival_agent.tenant_id,rival_agent.agent_id,rival_agent.context_id)=
                  (rival_source.tenant_id,rival_source.agent_id,rival_source.context_id)
            WHERE rival.tenant_id=support.tenant_id
              AND rival.context_id=support.context_id
              AND rival.source_kind='device_target'
              AND rival.alias_kind='address'
              AND rival.alias_value=support.alias_value
              AND rival_node.kind IN ('device','interface')
              AND COALESCE(rival_node.parent_entity_id,rival_node.id)<>@e@.entity_id
              AND rival.observed_at<=statement_timestamp()
              AND (rival.expires_at IS NULL OR rival.expires_at>statement_timestamp())
              AND rival_source.assigned_at<=rival.observed_at
              AND rival_source.assigned_at<=statement_timestamp()
              AND (rival_source.expires_at IS NULL OR rival_source.expires_at>statement_timestamp())
              AND rival_agent.assigned_at<=rival.observed_at
              AND rival_agent.assigned_at<=statement_timestamp()
              AND (rival_agent.expires_at IS NULL OR rival_agent.expires_at>statement_timestamp())
              AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
                  WHERE revoked.tenant_id=rival.tenant_id AND revoked.agent_id=rival.agent_id
                    AND revoked.revoked_at IS NOT NULL
                    AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
              AND EXISTS (SELECT 1 FROM agent_identities sender
                  WHERE sender.tenant_id=rival.tenant_id AND sender.agent_id=rival.agent_id
                    AND sender.serial=rival.sender_serial
                    AND sender.spiffe_id='spiffe://probectl/tenant/' || rival.tenant_id::text || '/entity/' || rival.agent_id
                    AND sender.revoked_at IS NULL
                    AND sender.issued_at<=rival.observed_at
                    AND sender.not_after>statement_timestamp())
       )
  )`
