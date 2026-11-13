// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Each peer's latest observation fences its old ASN, including expired or
// revoked newer observations. Current exact sender/router certificates and
// anchor/support are then proved by the shared current-evidence predicate.
// Roles require an explicit canonical ORIGIN router assignment. An inferred
// peer device identity is not that origin, even if it is independently current.
// An observed relationship and its clock never assert a live BGP session.
func loadInterfaceRolePeerInputs(ctx context.Context, sc tenancy.Scope, input InterfaceRoleInputs, budget *roleInputAdmission) ([]InterfaceRolePeerInput, error) {
	rows, err := sc.Q.Query(ctx, `WITH latest AS (
 SELECT e.agent_id,e.configured_ref,split_part(e.alias_value,'/as',1) AS peer,max(e.observed_at) AS observed
 FROM entity_evidence e WHERE e.tenant_id=$1 AND e.context_id=$2
 AND e.source_kind='bmp_peer' AND e.alias_kind='bmp_peer_id'
 AND (e.bmp_peer_session IS NULL OR e.bmp_peer_session->>'state'='up')
 AND e.observed_at<=transaction_timestamp()
 GROUP BY e.agent_id,e.configured_ref,split_part(e.alias_value,'/as',1))
 SELECT e.id::text,e.alias_value,e.source_ref,e.configured_ref,e.observed_at,`+interfaceRoleEvidenceExpirySQL()+`
 FROM entity_evidence e JOIN latest ON
 (latest.agent_id,latest.configured_ref,latest.peer,latest.observed)=
 (e.agent_id,e.configured_ref,split_part(e.alias_value,'/as',1),e.observed_at) `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.entity_id=$3 AND e.source_kind='bmp_peer'
 AND source.anchor_entity_id=$3 AND e.support_evidence_id IS NULL
 AND e.alias_kind='bmp_peer_id' AND (e.bmp_peer_session IS NULL OR e.bmp_peer_session->>'state'='up') AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.id LIMIT $4`,
		input.Scope.TenantID, input.Scope.ContextID, input.RouterID, budget.memory/2048+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []InterfaceRolePeerInput
	for rows.Next() {
		var row InterfaceRolePeerInput
		var alias, original, configured string
		if err := rows.Scan(&row.SourceID, &alias, &original, &configured, &row.ObservedAt, &row.ValidUntil); err != nil {
			return nil, err
		}
		if err := budget.charge(ctx, 2048+int64(len(alias)+len(original)+len(configured)), 1); err != nil {
			return nil, err
		}
		address, asn, err := parseInterfaceRolePeer(alias, original, configured)
		if err != nil {
			return nil, err
		}
		row.Address, row.ASN, row.SourceID = address, asn, "evidence/"+row.SourceID
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, ctx.Err()
}

func parseInterfaceRolePeer(alias, original, router string) (netip.Addr, uint32, error) {
	addressText, asnText, ok := strings.Cut(alias, "/as")
	address, addressErr := netip.ParseAddr(addressText)
	asn, asnErr := strconv.ParseUint(asnText, 10, 32)
	if !ok || addressErr != nil || asnErr != nil || asn == 0 || address.Is4In6() ||
		address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" ||
		address.String() != addressText || strconv.FormatUint(asn, 10) != asnText ||
		original != "bmp:router:"+router+":peer-asn:"+asnText {
		return netip.Addr{}, 0, entity.ErrInvalidClaim
	}
	return address, uint32(asn), nil
}
