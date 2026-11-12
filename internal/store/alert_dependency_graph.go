// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ValidateDependencyGraphInScope checks every operator reference in one
// tenant-scoped query. A stored graph cannot borrow another tenant's entity,
// agent, test or context. Configuration is not current health/hold authority.
func ValidateDependencyGraphInScope(ctx context.Context, sc tenancy.Scope, contextID string, graph *alert.DependencyGraphInput, maxBytes int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return alert.ErrDependencyEvidence
	}
	if graph == nil {
		return nil
	}
	if maxBytes < 4096 || int64(len(graph.Nodes)) > maxBytes/1024 {
		return ErrAlertDependencyBudget
	}
	remaining := maxBytes / 4
	for _, node := range graph.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost := int64(256) + int64(len(node.Parents))*128
		if cost > remaining {
			return ErrAlertDependencyBudget
		}
		remaining -= cost
	}
	if err := graph.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(graph.Nodes)
	if err != nil {
		return err
	}
	var matched int
	err = sc.Q.QueryRow(ctx, `SELECT count(*) FROM jsonb_to_recordset($3::jsonb)
 AS ref(entity_id uuid,agent_id uuid,test_id uuid)
 JOIN entities n ON (n.tenant_id,n.context_id,n.id)=($1::uuid,$2::uuid,ref.entity_id) AND n.kind='device'
 JOIN agents g ON (g.tenant_id,g.id)=(n.tenant_id,ref.agent_id) AND g.status<>'revoked'
 JOIN tests t ON (t.tenant_id,t.id)=(n.tenant_id,ref.test_id) AND t.enabled AND t.type='icmp'
 JOIN entity_path_test_contexts p ON (p.tenant_id,p.context_id,p.test_id)=(n.tenant_id,n.context_id,t.id)
 JOIN entity_test_contexts c ON (c.tenant_id,c.context_id,c.test_id)=(p.tenant_id,p.context_id,p.test_id)
 JOIN entity_source_contexts m ON
   (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref,m.anchor_entity_id)=
   (n.tenant_id,n.context_id,ref.agent_id::text,'path_agent',ref.test_id::text,n.id)
 JOIN entity_agent_contexts a ON (a.tenant_id,a.context_id,a.agent_id)=(m.tenant_id,m.context_id,m.agent_id)
 WHERE m.assigned_at<=statement_timestamp() AND a.assigned_at<=statement_timestamp()
   AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
   AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())`,
		sc.Tenant.String(), contextID, raw).Scan(&matched)
	if err != nil {
		return err
	}
	if matched != len(graph.Nodes) {
		return ErrAlertDependencyChanged
	}
	return ctx.Err()
}
