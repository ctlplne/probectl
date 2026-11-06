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

// InterfaceRoleFlowBinding is current source evidence, not row-supplied
// identity or permission. Callers authorize this context before source reads.
// Matching a flow requires its collector, exporter, protocol and domain, then
// a current canonical interface binding on this explicitly assigned router.
type InterfaceRoleFlowBinding struct {
	entity.Scope
	InterfaceRoleEvidenceClock
	AgentID, RouterID, SourceID string
	Exporter                    netip.Addr
	Protocol                    string
	Domain                      uint32
}

// FlowBindingsInScope shares the caller's application-role snapshot with its
// current user/context/source authorization. A later expired or revoked claim
// fences older identity. Inferred device identity cannot attest the emitter.
func (s *InterfaceRoleInputsStore) FlowBindingsInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, budget entity.InterfaceRolePolicyBudget) ([]InterfaceRoleFlowBinding, error) {
	want, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant != sc.Tenant || tenant.String() != want.TenantID || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	admission := roleInputAdmission{memory: budget.MemoryBytes, work: budget.WorkUnits}
	if err := admission.charge(ctx, 4096, 1); err != nil {
		return nil, err
	}
	var present int
	if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM entity_contexts WHERE tenant_id=$1 AND id=$2`, want.TenantID, want.ContextID).Scan(&present); err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `WITH latest AS (
 SELECT agent_id,configured_ref,alias_value,max(observed_at) AS observed
 FROM entity_evidence WHERE tenant_id=$1 AND context_id=$2
 AND source_kind='flow_exporter' AND alias_kind='flow_exporter_id'
 AND observed_at<=transaction_timestamp() GROUP BY agent_id,configured_ref,alias_value)
 SELECT e.id::text,e.agent_id,e.configured_ref,node.id::text,e.alias_value,e.source_ref,
 e.observed_at,`+interfaceRoleEvidenceExpirySQL()+`
 FROM entity_evidence e JOIN latest ON
 (latest.agent_id,latest.configured_ref,latest.alias_value,latest.observed)=
 (e.agent_id,e.configured_ref,e.alias_value,e.observed_at)
 JOIN entities node ON (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id)
 AND node.kind='device' `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.source_kind='flow_exporter'
 AND e.alias_kind='flow_exporter_id' AND source.anchor_entity_id=node.id AND e.support_evidence_id IS NULL
 AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.agent_id,e.configured_ref,e.alias_value,e.id LIMIT $3`,
		want.TenantID, want.ContextID, admission.memory/2048+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []InterfaceRoleFlowBinding{}
	for rows.Next() {
		var row InterfaceRoleFlowBinding
		var configured, alias, original string
		if err := rows.Scan(&row.SourceID, &row.AgentID, &configured, &row.RouterID, &alias, &original, &row.ObservedAt, &row.ValidUntil); err != nil {
			return nil, err
		}
		if err := admission.charge(ctx, 2048+int64(len(row.AgentID)+len(configured)+len(alias)+len(original)), 1); err != nil {
			return nil, err
		}
		row.Exporter, row.Protocol, row.Domain, err = parseInterfaceRoleFlowBinding(configured, alias, original)
		if err != nil {
			return nil, err
		}
		row.Scope, row.SourceID = want, "evidence/"+row.SourceID
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func parseInterfaceRoleFlowBinding(configured, alias, original string) (netip.Addr, string, uint32, error) {
	none := netip.Addr{}
	address, err := netip.ParseAddr(configured)
	if err != nil || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.String() != configured {
		return none, "", 0, entity.ErrInvalidClaim
	}
	rest, ok := strings.CutPrefix(alias, configured+"/")
	protocol, domainText, split := strings.Cut(rest, "/")
	domain, domainErr := strconv.ParseUint(domainText, 10, 32)
	if !ok || !split || domainErr != nil || strconv.FormatUint(domain, 10) != domainText || original != "flow:"+protocol+":domain:"+domainText {
		return none, "", 0, entity.ErrInvalidClaim
	}
	switch protocol {
	case "netflow5", "netflow9", "ipfix", "sflow5":
		return address, protocol, uint32(domain), nil
	default:
		return none, "", 0, entity.ErrInvalidClaim
	}
}
