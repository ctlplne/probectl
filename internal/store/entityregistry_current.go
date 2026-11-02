// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

// currentEntityEvidenceSQL is the registry's complete current-evidence
// predicate for a row aliased e. Consumers keep their explicit tenant/context
// predicates inside the same FORCE-RLS snapshot; this expression establishes
// source assignment, anchor/support, sender and BMP-origin validity. Reuse it
// when deriving tag facts instead of authorizing from historical evidence.
func currentEntityEvidenceSQL() string {
	return `(` + currentPhysicalNeighborSQL + `
			        AND e.observed_at <= statement_timestamp()
			        AND (e.expires_at IS NULL OR e.expires_at > statement_timestamp())
			        AND EXISTS (
			          SELECT 1 FROM entity_source_contexts m
			          JOIN entity_agent_contexts a ON
			            (a.tenant_id,a.agent_id,a.context_id)=
			            (m.tenant_id,m.agent_id,m.context_id)
			          WHERE (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
			                (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
		            AND ((e.support_evidence_id IS NULL AND
		                  (m.anchor_entity_id=e.entity_id OR EXISTS (
			                 SELECT 1 FROM entities child
			                  WHERE (child.tenant_id,child.context_id,child.id)=
			                        (e.tenant_id,e.context_id,e.entity_id)
		                    AND child.parent_entity_id=m.anchor_entity_id)))
		                 OR (m.anchor_entity_id IS NULL AND ` + currentInferredSupportSQL("e") + `))
			            AND m.assigned_at<=statement_timestamp()
			            AND m.assigned_at<=e.observed_at
			            AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
			            AND a.assigned_at<=statement_timestamp()
			            AND a.assigned_at<=e.observed_at
			            AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
			            AND NOT EXISTS (SELECT 1 FROM agent_identities i
			              WHERE i.tenant_id=e.tenant_id AND i.agent_id=e.agent_id
			                AND i.revoked_at IS NOT NULL
			                AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete'))
			        AND EXISTS (
			          SELECT 1 FROM agent_identities sender
			           WHERE sender.tenant_id=e.tenant_id
			             AND sender.agent_id=e.agent_id
			             AND sender.serial=e.sender_serial
			             AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
			             AND sender.revoked_at IS NULL
			             AND sender.issued_at <= e.observed_at
			             AND sender.not_after > statement_timestamp())
			        AND (e.source_kind <> 'bmp_peer' OR EXISTS (
			          SELECT 1 FROM agent_identities origin
			           WHERE origin.tenant_id=e.tenant_id
			             AND origin.agent_id=e.configured_ref
			             AND origin.serial=e.origin_serial
			             AND origin.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/bmp/' || e.configured_ref
			             AND origin.revoked_at IS NULL
			             AND origin.issued_at <= e.observed_at
			             AND origin.not_after > statement_timestamp())))`
}
