// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

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
	refs := dependencyGraphReferences(graph)
	// The relation sizes of a newly imported context may not yet be reflected
	// in PostgreSQL statistics. A correlated reference lookup can then scan
	// that entire context once per node. Read each complete fact family once
	// in one statement/snapshot, and match exact source triples below.
	agents := make([]string, 0)
	seenAgents := map[string]bool{}
	for _, agent := range refs.agents {
		if !seenAgents[agent] {
			seenAgents[agent] = true
			agents = append(agents, agent)
		}
	}
	rows, err := sc.Q.Query(ctx, dependencyGraphReferenceFactsSQL, pgx.QueryExecModeDescribeExec,
		sc.Tenant.String(), contextID, refs.entities, agents, refs.tests, refs.tests, agents)
	if err != nil {
		return fmt.Errorf("current dependency reference lookup: %w", err)
	}
	defer rows.Close()
	facts := map[dependencyReferenceFact]bool{}
	sources := map[dependencyReferenceSource]string{}
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var family, id, agent, test string
		if err := rows.Scan(&family, &id, &agent, &test); err != nil {
			return err
		}
		// Charge every returned fact, including any nonmatching source tuple.
		// A cost refusal never validates a successful prefix of the graph.
		charge := int64(128) + int64(len(family)+len(id)+len(agent)+len(test))*2
		if charge > remaining {
			return ErrAlertDependencyBudget
		}
		remaining -= charge
		switch family {
		case "source":
			sources[dependencyReferenceSource{agent, test}] = id
		case "entity", "agent", "test", "path", "context", "assignment":
			facts[dependencyReferenceFact{family, id}] = true
		default:
			return alert.ErrDependencyEvidence
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("current dependency reference lookup: %w", err)
	}
	for _, node := range graph.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sources[dependencyReferenceSource{node.AgentID, node.TestID}] != node.EntityID {
			return ErrAlertDependencyChanged
		}
		for _, fact := range []dependencyReferenceFact{
			{"entity", node.EntityID}, {"agent", node.AgentID}, {"test", node.TestID},
			{"path", node.TestID}, {"context", node.TestID}, {"assignment", node.AgentID},
		} {
			if !facts[fact] {
				return ErrAlertDependencyChanged
			}
		}
	}
	return ctx.Err()
}

// UNION ALL keeps every family in one temporal/RLS snapshot without a join
// that can multiply context populations. References are matched as complete
// triples in Go; independent membership never confers source authority.
const dependencyGraphReferenceFactsSQL = `
 SELECT 'source',m.anchor_entity_id::text,m.agent_id,m.source_ref
 FROM entity_source_contexts m
 WHERE m.tenant_id=$1 AND m.context_id=$2 AND m.source_kind='path_agent'
   AND m.agent_id=ANY($4::text[]) AND m.source_ref=ANY($6::text[])
   AND m.anchor_entity_id=ANY($3::uuid[]) AND m.assigned_at<=statement_timestamp()
   AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
 UNION ALL
 SELECT 'entity',n.id::text,'','' FROM entities n
 WHERE n.tenant_id=$1 AND n.context_id=$2 AND n.id=ANY($3::uuid[]) AND n.kind='device'
 UNION ALL
 SELECT 'agent',g.id::text,'','' FROM agents g
 WHERE g.tenant_id=$1 AND $2::uuid IS NOT NULL AND g.id=ANY($7::uuid[]) AND g.status<>'revoked'
 UNION ALL
 SELECT 'test',t.id::text,'','' FROM tests t
 WHERE t.tenant_id=$1 AND $2::uuid IS NOT NULL AND t.id=ANY($5::uuid[]) AND t.enabled AND t.type='icmp'
 UNION ALL
 SELECT 'path',p.test_id::text,'','' FROM entity_path_test_contexts p
 WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.test_id=ANY($5::uuid[])
 UNION ALL
 SELECT 'context',c.test_id::text,'','' FROM entity_test_contexts c
 WHERE c.tenant_id=$1 AND c.context_id=$2 AND c.test_id=ANY($5::uuid[])
 UNION ALL
 SELECT 'assignment',a.agent_id,'','' FROM entity_agent_contexts a
 WHERE a.tenant_id=$1 AND a.context_id=$2 AND a.agent_id=ANY($4::text[])
   AND a.assigned_at<=statement_timestamp() AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())`

type dependencyReferenceFact struct{ family, id string }
type dependencyReferenceSource struct{ agent, test string }

type dependencyReferences struct {
	entities, agents, tests []string
}

// The graph has already passed finite admission and complete UUID/edge
// validation. Transfer only its source keys, exposing the population to the
// planner without repeatedly encoding every parent edge in lock queries.
func dependencyGraphReferences(graph *alert.DependencyGraphInput) dependencyReferences {
	refs := dependencyReferences{
		entities: make([]string, len(graph.Nodes)),
		agents:   make([]string, len(graph.Nodes)),
		tests:    make([]string, len(graph.Nodes)),
	}
	for i, node := range graph.Nodes {
		refs.entities[i], refs.agents[i], refs.tests[i] = node.EntityID, node.AgentID, node.TestID
	}
	return refs
}
