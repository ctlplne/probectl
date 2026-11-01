// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

// currentPhysicalNeighborSQL is embedded in current-evidence queries where
// `e` is the signed local LLDP/CDP row. A stored physical edge alone is not
// authority: its remote SNMP support can expire, be revoked or become
// ambiguous after another device claims the same address/name.
const currentPhysicalNeighborSQL = `
  (e.alias_kind <> 'physical_neighbor_id' OR EXISTS (
    SELECT 1 FROM entity_links physical
     WHERE (physical.tenant_id,physical.context_id,physical.evidence_id)=
           (e.tenant_id,e.context_id,e.id)
       AND physical.kind='physical'
       AND physical.from_entity_id=e.entity_id
       AND (SELECT COUNT(DISTINCT COALESCE(n.parent_entity_id,n.id))=1
                   AND BOOL_OR(COALESCE(n.parent_entity_id,n.id)=physical.to_entity_id)
              FROM entity_evidence remote
              JOIN entities n ON (n.tenant_id,n.context_id,n.id)=
                                 (remote.tenant_id,remote.context_id,remote.entity_id)
              JOIN entity_source_contexts m ON
                   (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
                   (remote.tenant_id,remote.context_id,remote.agent_id,
                    remote.source_kind,remote.configured_ref)
                 AND m.anchor_entity_id=COALESCE(n.parent_entity_id,n.id)
              JOIN entity_agent_contexts a ON
                   (a.tenant_id,a.agent_id,a.context_id)=
                   (m.tenant_id,m.agent_id,m.context_id)
             WHERE remote.tenant_id=e.tenant_id
               AND remote.context_id=e.context_id
               AND remote.alias_kind=CASE
                     WHEN e.neighbor_management_address IS NOT NULL THEN 'address'
                     ELSE 'snmp_device_id' END
               AND remote.alias_value=COALESCE(e.neighbor_management_address,
                                                e.neighbor_device_name)
               AND remote.source_kind='device_target'
               AND n.kind IN ('device','interface')
               AND remote.observed_at<=statement_timestamp()
               AND (remote.expires_at IS NULL OR remote.expires_at>statement_timestamp())
               AND m.assigned_at<=statement_timestamp()
               AND m.assigned_at<=remote.observed_at
               AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
               AND a.assigned_at<=statement_timestamp()
               AND a.assigned_at<=remote.observed_at
               AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
               AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
                   WHERE revoked.tenant_id=remote.tenant_id
                     AND revoked.agent_id=remote.agent_id
                     AND revoked.revoked_at IS NOT NULL
                     AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
               AND EXISTS (SELECT 1 FROM agent_identities sender
                   WHERE sender.tenant_id=remote.tenant_id
                     AND sender.agent_id=remote.agent_id
                     AND sender.serial=remote.sender_serial
                     AND sender.spiffe_id='spiffe://probectl/tenant/' || remote.tenant_id::text || '/entity/' || remote.agent_id
                     AND sender.revoked_at IS NULL
                     AND sender.issued_at<=remote.observed_at
                     AND sender.not_after>statement_timestamp()))))`
