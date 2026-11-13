// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CurrentSourceAddressInScope proves that the exact authenticated sender has
// current address evidence for the resolved device at the fault's time. An
// interface IP projects to its parent, while an unanchored flow/BMP row still
// requires its exact independent SNMP support. The caller separately requires
// a globally unambiguous ResolveAliasInScope result in this tenant/context.
func CurrentSourceAddressInScope(ctx context.Context, sc tenancy.Scope,
	scope entity.Scope, alias entity.AliasKey, source entity.SourceKey,
	serial, expectedEntityID string, observedAt time.Time) (bool, error) {
	want, err := scope.Normalize()
	if err != nil || want.TenantID != sc.Tenant.String() {
		return false, entity.ErrScopeMismatch
	}
	key, err := alias.Normalize()
	if err != nil || key.Kind != entity.AddressAlias {
		return false, entity.ErrInvalidAlias
	}
	source, err = source.Normalize()
	if err != nil {
		return false, err
	}
	entityID, err := validRegistryUUID(expectedEntityID)
	if err != nil || serial == "" || observedAt.IsZero() {
		return false, entity.ErrInvalidClaim
	}
	var evidenceID string
	err = sc.Q.QueryRow(ctx, `
		SELECT e.id::text
		  FROM entity_evidence e
		  JOIN entities node ON
		       (node.tenant_id,node.context_id,node.id)=
		       (e.tenant_id,e.context_id,e.entity_id)
		  JOIN entity_source_contexts m ON
		       (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
		       (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
		     AND ((e.support_evidence_id IS NULL AND
		           m.anchor_entity_id=COALESCE(node.parent_entity_id,e.entity_id))
		          OR (m.anchor_entity_id IS NULL AND `+currentInferredSupportSQL("e")+`))
		  JOIN entity_agent_contexts a ON
		       (a.tenant_id,a.agent_id,a.context_id)=
		       (m.tenant_id,m.agent_id,m.context_id)
		  JOIN agent_identities sender ON
		       (sender.tenant_id,sender.agent_id,sender.serial)=
		       (e.tenant_id,e.agent_id,e.sender_serial)
		 WHERE e.tenant_id=$1 AND e.context_id=$2
		   AND e.alias_kind='address' AND e.alias_value=$3
		   AND COALESCE(node.parent_entity_id,e.entity_id)=$4
		   AND e.agent_id=$5 AND e.source_kind=$6 AND e.configured_ref=$7
		   AND e.sender_serial=$8 AND e.observed_at<=$9
		   AND e.observed_at<=statement_timestamp()
		   AND (e.expires_at IS NULL OR e.expires_at>statement_timestamp())
		   AND m.assigned_at<=e.observed_at AND m.assigned_at<=statement_timestamp()
		   AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
		   AND a.assigned_at<=e.observed_at AND a.assigned_at<=statement_timestamp()
		   AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
		   AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
		       WHERE revoked.tenant_id=e.tenant_id AND revoked.agent_id=e.agent_id
		         AND revoked.revoked_at IS NOT NULL
		         AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		   AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
		   AND sender.revoked_at IS NULL AND sender.issued_at<=e.observed_at
		   AND sender.not_after>statement_timestamp()
		   AND (e.bmp_peer_session IS NULL OR e.bmp_peer_session->>'state'='up')
 AND (e.source_kind<>'bmp_peer' OR EXISTS (
		       SELECT 1 FROM agent_identities origin
		        WHERE origin.tenant_id=e.tenant_id
		          AND origin.agent_id=e.configured_ref
		          AND origin.serial=e.origin_serial
		          AND origin.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/bmp/' || e.configured_ref
		          AND origin.revoked_at IS NULL
		          AND origin.issued_at<=e.observed_at
		          AND origin.not_after>statement_timestamp()))
		 ORDER BY e.observed_at DESC,e.id
		 LIMIT 1 FOR SHARE OF e,node,m,a,sender`,
		want.TenantID, want.ContextID, key.Value, entityID, source.AgentID,
		string(source.Kind), source.SourceRef, serial, observedAt).Scan(&evidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
