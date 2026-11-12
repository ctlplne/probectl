// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// LockDependencySourcesInScope retains source authority through publication.
// The caller first holds the existing rule/audit and incident-correlation
// locks. In particular, locking the graph's current assignments alone would
// not serialize a certificate revocation, test edit or agent revocation.
// Every candidate is consumed; resource refusal returns no hold authority.
func LockDependencySourcesInScope(ctx context.Context, sc tenancy.Scope, contextID string, graph *alert.DependencyGraphInput, maxBytes int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || graph == nil {
		return alert.ErrDependencyEvidence
	}
	if maxBytes < 4096 || int64(len(graph.Nodes)) > maxBytes/512 {
		return ErrAlertDependencyBudget
	}
	if _, err := validRegistryUUID(contextID); err != nil {
		return err
	}
	if err := graph.Validate(); err != nil {
		return err
	}
	refs := dependencyGraphReferences(graph)
	const requested = `WITH refs AS (
 SELECT * FROM unnest($3::uuid[],$4::text[],$5::uuid[]) AS input(entity_id,agent_id,test_id)
 ) `
	remaining := maxBytes / 256
	for _, query := range []string{
		`SELECT 1 FROM agents g WHERE g.tenant_id=$1 AND $2::uuid IS NOT NULL
 AND g.id IN (SELECT agent_id::uuid FROM refs)
 ORDER BY g.id FOR SHARE OF g`,
		`SELECT 1 FROM agent_identities i WHERE i.tenant_id=$1 AND $2::uuid IS NOT NULL
 AND i.agent_id IN (SELECT agent_id FROM refs)
 ORDER BY i.id FOR SHARE OF i`,
		`SELECT 1 FROM tests t WHERE t.tenant_id=$1 AND $2::uuid IS NOT NULL
 AND t.id IN (SELECT test_id FROM refs)
 ORDER BY t.id FOR SHARE OF t`,
		`SELECT 1 FROM entity_contexts c WHERE c.tenant_id=$1 AND c.id=$2
 FOR SHARE OF c`,
		`SELECT 1 FROM entities n WHERE n.tenant_id=$1 AND n.context_id=$2
 AND n.id IN (SELECT entity_id FROM refs)
 ORDER BY n.id FOR SHARE OF n`,
		`SELECT 1 FROM entity_agent_contexts a WHERE a.tenant_id=$1 AND a.context_id=$2
 AND a.agent_id IN (SELECT agent_id FROM refs)
 ORDER BY a.agent_id FOR SHARE OF a`,
		`SELECT 1 FROM entity_source_contexts m WHERE m.tenant_id=$1 AND m.context_id=$2
 AND m.source_kind='path_agent' AND EXISTS(SELECT 1 FROM refs
 WHERE (m.agent_id,m.source_ref)=(refs.agent_id,refs.test_id::text))
 ORDER BY m.agent_id,m.source_ref FOR SHARE OF m`,
		`SELECT 1 FROM entity_test_contexts c WHERE c.tenant_id=$1 AND c.context_id=$2
 AND c.test_id IN (SELECT test_id FROM refs)
 ORDER BY c.test_id FOR SHARE OF c`,
		`SELECT 1 FROM entity_path_test_contexts p WHERE p.tenant_id=$1 AND p.context_id=$2
 AND p.test_id IN (SELECT test_id FROM refs)
 ORDER BY p.test_id FOR SHARE OF p`,
	} {
		rows, err := sc.Q.Query(ctx, requested+query, pgx.QueryExecModeDescribeExec, sc.Tenant.String(), contextID, refs.entities, refs.agents, refs.tests)
		if err != nil {
			return err
		}
		for rows.Next() {
			remaining--
			if remaining < 0 {
				rows.Close()
				return ErrAlertDependencyBudget
			}
			var one int
			if err := rows.Scan(&one); err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return ValidateDependencyGraphInScope(ctx, sc, contextID, graph, maxBytes)
}

// DependencyCauseIncidents returns at most one current canonical case per source.
// Ambiguity is not resolved by recency or a UUID winner. RLS, context and
// canonical identity all apply before considering the case a hold cause.
func (Incidents) DependencyCauseIncidents(ctx context.Context, sc tenancy.Scope, contextID string, entityIDs []string, maxBytes int64) (map[string]string, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, alert.ErrDependencyEvidence
	}
	if len(entityIDs) == 0 || int64(len(entityIDs)) > maxBytes/512 {
		return nil, ErrAlertDependencyBudget
	}
	if _, err := validRegistryUUID(contextID); err != nil {
		return nil, err
	}
	for _, id := range entityIDs {
		if _, err := validRegistryUUID(id); err != nil {
			return nil, err
		}
	}
	rows, err := sc.Q.Query(ctx, `SELECT entity_id::text,id::text FROM incidents
 WHERE tenant_id=$1 AND entity_context_id=$2 AND entity_id=ANY($3::uuid[])
 AND identity_lookup_attempted AND status='open'
 ORDER BY entity_id,id FOR UPDATE`, sc.Tenant.String(), contextID, entityIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, len(entityIDs))
	remaining := maxBytes / 512
	for rows.Next() {
		remaining--
		if remaining < 0 {
			return nil, ErrAlertDependencyBudget
		}
		var entityID, id string
		if err := rows.Scan(&entityID, &id); err != nil {
			return nil, err
		}
		if out[entityID] != "" {
			return nil, alert.ErrDependencyEvidence
		}
		out[entityID] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// DependencyParentIncidents is only a history lookup for an already-authorized
// current episode. These prior relationships confer no current hold authority.
// Include resolved parents so recovery closes their visible child history too.
func (Incidents) DependencyParentIncidents(ctx context.Context, sc tenancy.Scope, contextID, entityID, key, transition string, since time.Time, maxBytes int64) ([]string, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || maxBytes < 4096 {
		return nil, alert.ErrDependencyEvidence
	}
	if err := dependencyHistoryKey(contextID, entityID, key); err != nil || since.IsZero() {
		return nil, alert.ErrDependencyEvidence
	}
	if transition != "" {
		if _, err := validRegistryUUID(transition); err != nil {
			return nil, err
		}
	}
	rows, err := sc.Q.Query(ctx, `SELECT i.id::text FROM incidents i
 WHERE i.tenant_id=$1 AND EXISTS(SELECT 1 FROM incident_signals s
 WHERE (s.tenant_id,s.incident_id)=(i.tenant_id,i.id)
 AND s.entity_context_id=$2 AND s.entity_id=$3 AND s.identity_lookup_attempted
 AND s.attributes->>'dependency.notification_key'=$4
 AND s.attributes->>'dependency.firing_since'=$5
 AND NULLIF(s.attributes->>'dependency.transition_id','') IS NOT DISTINCT FROM NULLIF($6::text,'')
 AND s.attributes->>'dependency.state'='held')
 ORDER BY i.id FOR UPDATE OF i`, sc.Tenant.String(), contextID, entityID, key, since.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), transition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		if int64(len(ids)) >= maxBytes/512 {
			return nil, ErrAlertDependencyBudget
		}
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// AppendDependencyRelease is idempotent for an episode's transition. The
// caller holds the selected parent row and tenant correlation lock, preventing
// a crash/retry from appending another release with a different wall clock.
func (repo Incidents) AppendDependencyRelease(ctx context.Context, sc tenancy.Scope, parent string, sig incident.Signal) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || sig.TenantID != sc.Tenant.String() || !sig.IdentityLookupAttempted {
		return alert.ErrDependencyEvidence
	}
	if _, err := validRegistryUUID(parent); err != nil {
		return err
	}
	if err := dependencyHistoryKey(sig.IdentityContextID, sig.IdentityEntityID, sig.Attributes["dependency.notification_key"]); err != nil {
		return err
	}
	state := sig.Attributes["dependency.state"]
	if state != "released" && state != "resolved" {
		return alert.ErrDependencyEvidence
	}
	if _, err := time.Parse(time.RFC3339Nano, sig.Attributes["dependency.firing_since"]); err != nil {
		return alert.ErrDependencyEvidence
	}
	if transition := sig.Attributes["dependency.transition_id"]; transition != "" {
		if _, err := validRegistryUUID(transition); err != nil {
			return err
		}
	}
	var present bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_signals s
 WHERE s.tenant_id=$1 AND s.incident_id=$2 AND s.entity_context_id=$3
 AND s.entity_id=$4 AND s.identity_lookup_attempted
 AND s.attributes->>'dependency.notification_key'=$5
 AND s.attributes->>'dependency.firing_since'=$6
 AND s.attributes->>'dependency.state'=$7
 AND NULLIF(s.attributes->>'dependency.transition_id','') IS NOT DISTINCT FROM NULLIF($8::text,''))`,
		sc.Tenant.String(), parent, sig.IdentityContextID, sig.IdentityEntityID,
		sig.Attributes["dependency.notification_key"], sig.Attributes["dependency.firing_since"], sig.Attributes["dependency.state"], sig.Attributes["dependency.transition_id"]).Scan(&present)
	if err != nil || present {
		return err
	}
	_, err = repo.AppendSignal(ctx, sc, parent, sig)
	return err
}

func dependencyHistoryKey(contextID, entityID, key string) error {
	if _, err := validRegistryUUID(contextID); err != nil {
		return err
	}
	if _, err := validRegistryUUID(entityID); err != nil {
		return err
	}
	digest, err := hex.DecodeString(key)
	if err != nil || len(digest) != 32 || strings.ToLower(key) != key {
		return alert.ErrDependencyEvidence
	}
	return nil
}
