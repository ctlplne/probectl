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

// SubscriberTestsInScope resolves explicit tag selections to existing
// canonical ICMP measurement points. Shared targets supply no identity.
func SubscriberTestsInScope(ctx context.Context, sc tenancy.Scope, allowed []string, tagID, subscriber string, memory int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity, string) error,
) ([]IncidentConfiguredTest, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if memory < 8192 {
		return nil, ErrClientReportBudget
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT m.context_id::text,m.anchor_entity_id::text,t.id::text,m.agent_id
 FROM tenant_tag_assignments a
 JOIN tests t ON t.tenant_id=$1 AND t.id=a.test_id AND t.type='icmp' AND t.enabled
 JOIN entity_source_contexts m ON m.tenant_id=$1 AND m.context_id=a.context_id
 AND m.source_kind='path_agent' AND m.source_ref=t.id::text AND m.anchor_entity_id IS NOT NULL
 WHERE a.tenant_id=$1 AND a.context_id=ANY($2::uuid[]) AND a.tag_id=$3 AND a.value=$4 AND a.target_kind='test'
 AND m.assigned_at<=transaction_timestamp() AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 ORDER BY m.context_id,m.anchor_entity_id,t.id,m.agent_id LIMIT $5`, bound.String(), allowed, tagID, subscriber, memory/2048+1)
	if err != nil {
		return nil, err
	}
	var contexts, entities []string
	var selected []IncidentConfiguredTest
	members := make(map[string]IncidentImpactEntity)
	for rows.Next() {
		if int64(len(selected)) >= memory/2048 {
			rows.Close()
			return nil, ErrClientReportBudget
		}
		var binding IncidentConfiguredTest
		if err := rows.Scan(&binding.ContextID, &binding.EntityID, &binding.TestID, &binding.AgentID); err != nil {
			rows.Close()
			return nil, err
		}
		selected = append(selected, binding)
		key := binding.ContextID + ":" + binding.EntityID
		if _, known := members[key]; !known {
			members[key] = IncidentImpactEntity{ContextID: binding.ContextID, EntityID: binding.EntityID}
			contexts, entities = append(contexts, binding.ContextID), append(entities, binding.EntityID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(selected) == 0 {
		return nil, err
	}
	return readIncidentConfiguredTests(ctx, sc, contexts, entities, members, generation, memory/2, authorize, selected)
}
