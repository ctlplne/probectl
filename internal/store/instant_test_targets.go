// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"slices"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// Targets resolves a complete selector within the tenant's current agent and
// tag snapshot. The caller still authorizes each returned agent before dispatch.
func (InstantTestRuns) Targets(ctx context.Context, sc tenancy.Scope, selection testspec.InstantSelection, probeType string, memoryBytes int64) ([]Agent, error) {
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	if memoryBytes <= 0 {
		return nil, ErrInstantRunBudget
	}
	var contextID any
	if selection.Tag != nil {
		contextID = selection.Tag.ContextID
	}
	const hasLiveIdentity = `EXISTS (
     SELECT 1 FROM agent_identities i
     WHERE i.tenant_id=a.tenant_id AND i.agent_id=a.id::text AND i.spiffe_id=a.spiffe_id
       AND i.revoked_at IS NULL AND i.issued_at<=transaction_timestamp()
       AND i.not_after>transaction_timestamp())`
	rows, err := sc.Q.Query(ctx, `SELECT `+agentCols+` FROM agents a
 WHERE a.tenant_id=$1 AND (COALESCE(cardinality($2::uuid[]),0)=0 OR a.id=ANY($2::uuid[]))
   AND ($3::text='' OR a.labels->>'site'=$3)
   AND ($4::uuid IS NULL OR (EXISTS (SELECT 1 FROM entity_agent_contexts c
          WHERE (c.tenant_id,c.agent_id,c.context_id)=(a.tenant_id,a.id::text,$4)
            AND c.assigned_at<=transaction_timestamp()
            AND (c.expires_at IS NULL OR c.expires_at>transaction_timestamp()))
          AND `+hasLiveIdentity+`))
 ORDER BY a.id`, tenant, selection.AgentIDs, selection.Site, contextID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	charge := func(fields ...string) error {
		cost := int64(2048 + maxInstantResultProjectionBytes)
		for _, field := range fields {
			cost += int64(len(field))
		}
		if cost > memoryBytes {
			return ErrInstantRunBudget
		}
		memoryBytes -= cost
		return nil
	}
	var agents []Agent
	for rows.Next() {
		var agent Agent
		if err := scanAgent(rows, &agent); err != nil {
			return nil, err
		}
		if err := charge(agent.ID, agent.Name, agent.Hostname); err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(selection.AgentIDs) > 0 && len(agents) != len(selection.AgentIDs) {
		return nil, ErrInstantRunUnavailable
	}
	if selection.Tag != nil {
		agents, err = instantAgentsByTag(ctx, sc, agents, *selection.Tag, memoryBytes, charge)
		if err != nil {
			return nil, err
		}
	}
	if len(agents) == 0 {
		return nil, ErrInstantRunUnavailable
	}
	// Resolve membership first. A site or tag can include an offline or
	// incompatible agent. Refuse that run as a whole rather than silently
	// dispatching to only the agents that pass readiness.
	ids := make([]string, 0, len(agents))
	for _, agent := range agents {
		ids = append(ids, agent.ID)
	}
	var ready int64
	err = sc.Q.QueryRow(ctx, `SELECT count(*) FROM agents a
 WHERE a.tenant_id=$1 AND a.id=ANY($2::uuid[])
   AND a.capabilities ?& ARRAY[$3::text,$4::text]
   AND a.test_set_version>0 AND a.status<>'revoked'
   AND a.last_seen_at>=transaction_timestamp()-make_interval(secs=>$5)
   AND `+hasLiveIdentity, tenant, ids, probeType, testspec.InstantTestCapability, AgentOnlineWindow.Seconds()).Scan(&ready)
	if err != nil {
		return nil, err
	}
	if ready != int64(len(agents)) {
		return nil, ErrInstantRunUnavailable
	}
	return agents, nil
}

func instantAgentsByTag(ctx context.Context, sc tenancy.Scope, agents []Agent, selection testspec.InstantAgentTag, memoryBytes int64, charge func(...string) error) ([]Agent, error) {
	scope := tags.Scope{TenantID: sc.Tenant.String(), ContextID: selection.ContextID}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1)`, scope.TenantID).Scan(&revision); err != nil {
		return nil, err
	}
	definitions, err := loadTagDefinitions(ctx, sc, scope, charge)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(definitions, func(definition tags.Definition) bool { return definition.ID == selection.TagID }) {
		return nil, ErrInstantRunUnavailable
	}
	snapshot, err := loadTagContextSnapshot(ctx, sc, scope, revision, definitions, charge)
	if err != nil {
		return nil, err
	}
	matching := agents[:0]
	for _, agent := range agents {
		fact, err := loadOwnedTagSubject(ctx, sc, scope, TagSubjectReference{Kind: "agent", ID: agent.ID}, memoryBytes, charge)
		if err != nil {
			return nil, err
		}
		items, err := snapshot.ResolveContext(ctx, fact)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(items, func(item tags.Resolved) bool {
			return item.TagID == selection.TagID && item.Value == selection.Value
		}) {
			matching = append(matching, agent)
		}
	}
	return matching, nil
}
