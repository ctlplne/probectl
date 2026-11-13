// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import "strings"

// A configured-test alias grants no lasting test binding. Recheck the exact
// enabled definition and metadata context even in ordinary alias/evidence
// reads, after the outer tenant/source predicates. Other alias families do not
// acquire this extra query or a synthetic-test identity.
const currentConfiguredProbeSQL = `(e.alias_kind<>'configured_test_id' OR EXISTS (
 SELECT 1 FROM tests configured
 JOIN entity_test_contexts binding ON (binding.tenant_id,binding.test_id)=(configured.tenant_id,configured.id)
 JOIN entity_source_contexts probe_source ON
 (probe_source.tenant_id,probe_source.context_id,probe_source.agent_id,probe_source.source_kind,probe_source.source_ref)=
 (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
 JOIN entity_agent_contexts probe_agent ON
 (probe_agent.tenant_id,probe_agent.context_id,probe_agent.agent_id)=(probe_source.tenant_id,probe_source.context_id,probe_source.agent_id)
 WHERE configured.tenant_id=e.tenant_id AND configured.id=CASE
 WHEN e.configured_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN e.configured_ref::uuid END
 AND binding.context_id=e.context_id AND configured.enabled
 AND configured.type=e.probe_outcome->>'canary_type'
 AND GREATEST(configured.updated_at,binding.assigned_at,probe_source.assigned_at,probe_agent.assigned_at)
 <=(e.probe_outcome->>'started_at')::timestamptz))`

// A tag read snapshot keeps one temporal reference as well as one MVCC view.
// Derive it from the complete predicate, including nested source/support
// checks, so expiry between SELECTs cannot mix fact epochs in one result.
func currentEntityEvidenceSnapshotSQL(configured ...bool) string {
	return strings.ReplaceAll(currentEntityEvidenceSQL(configured...), "statement_timestamp()", "transaction_timestamp()")
}

// currentEntityEvidenceSQL is the registry's complete current-evidence
// predicate for a row aliased e. Consumers keep their explicit tenant/context
// predicates inside the same FORCE-RLS snapshot; this expression establishes
// source assignment, anchor/support, sender and BMP-origin validity. Reuse it
// when deriving tag facts instead of authorizing from historical evidence.
func currentEntityEvidenceSQL(configured ...bool) string {
	probeGuard := currentConfiguredProbeSQL
	if len(configured) > 0 && !configured[0] {
		// Only callers that already constrain alias_kind to another family
		// may omit this lookup; complete evidence lists retain it by default.
		probeGuard = "TRUE"
	}
	return `(` + currentPhysicalNeighborSQL + ` AND ` + probeGuard + `
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
