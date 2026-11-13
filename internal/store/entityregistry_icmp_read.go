// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// ICMPHealth is an operation-local source snapshot, never a notification hold
// or an authorization token. The caller must authorize the current owner and
// source before reading, and re-read current authority when publishing a hold.
// Unknown includes missing, conflicted, stale, withdrawn and incomplete data.
type ICMPHealth struct {
	State, Reason            string
	EvidenceID, SenderSerial string
	Observation              entity.Observation
	AsOf, FreshUntil         time.Time
}

// ReadICMPHealthInScope reads one exact configured source, not an address-wide
// or tenant-wide winner. All authority is read in one SQL snapshot, including
// the current executable definition, erasure cutoff, canonical anchor, source
// assignments and exact issued sender. The newest unknown sample supersedes
// older health; equal-clock conflicting observations never choose a UUID winner.
func (s *EntityRegistry) ReadICMPHealthInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, source entity.SourceKey, entityID string, freshness time.Duration, maxBytes int64) (ICMPHealth, error) {
	unknown := ICMPHealth{State: "unknown", Reason: "unavailable"}
	bound, ok := tenancy.FromContext(ctx)
	want, err := scope.Normalize()
	if !ok || bound != sc.Tenant || err != nil || want.TenantID != bound.String() {
		return unknown, entity.ErrScopeMismatch
	}
	if s == nil || s.pool == nil || sc.Q == nil {
		return unknown, ErrEntityRegistryUnavailable
	}
	key, err := source.Normalize()
	if err != nil || key.Kind != entity.PathAgent || freshness <= 0 || maxBytes < 4096 {
		return unknown, entity.ErrInvalidClaim
	}
	if _, err := validRegistryUUID(key.SourceRef); err != nil {
		return unknown, entity.ErrInvalidClaim
	}
	if _, err := validRegistryUUID(entityID); err != nil {
		return unknown, entity.ErrInvalidClaim
	}
	if err := ctx.Err(); err != nil {
		return unknown, err
	}

	return scanICMPHealth(sc.Q.QueryRow(ctx, currentICMPHealthSQL(), want.TenantID, want.ContextID, key.AgentID, key.SourceRef, entityID, maxBytes/16), key, entityID, freshness)
}

// Keep the single-source and population readers on the identical current,
// erasure, exact-sender and executable-definition SQL door.
// Transfer admission precedes JSON decoding. LIMIT 1 selects the latest
// sample; EXISTS checks all equal-clock candidates for conflicting evidence.
// Metadata joins bind the same exact source keys used by the latest-row WHERE,
// allowing point lookups even while a fresh tenant's statistics are incomplete.
func currentICMPHealthSQL(population ...bool) string {
	agentParameter, sourceParameter, entityParameter, sizeParameter := "$3", "$4", "$5", "$6"
	if len(population) > 0 && population[0] {
		agentParameter, sourceParameter, entityParameter = "requested.agent_id", "requested.source_ref", "requested.entity_id"
	}
	return "SELECT " + currentICMPHealthColumnsSQL(entityParameter, sizeParameter) + " FROM " + currentICMPLatestSQL(agentParameter, sourceParameter) + " e" + currentICMPHealthJoinsSQL(agentParameter, sourceParameter)
}

// Keep metadata joins outside the per-source latest-row lookup. Planning all
// source/test/identity joins inside LATERAL can rebuild tenant-wide joins once
// per requested source when the freshly populated tenant has sparse statistics.
func currentICMPHealthPopulationSQL() string {
	return `WITH requested AS (
 SELECT ordinality,agent_id AS agent_id,source_ref,entity_id
 FROM unnest($3::text[],$4::text[],$5::uuid[]) WITH ORDINALITY AS input(agent_id,source_ref,entity_id,ordinality)
 ) SELECT requested.ordinality,` + currentICMPHealthColumnsSQL("requested.entity_id", "$6") +
		" FROM requested JOIN LATERAL " + currentICMPLatestSQL("requested.agent_id", "requested.source_ref") + " e ON true" +
		currentICMPHealthJoinsSQL("requested.agent_id", "requested.source_ref") + " ORDER BY requested.ordinality"
}

func currentICMPHealthColumnsSQL(entityParameter, sizeParameter string) string {
	return `e.id::text,e.observation_id::text,e.entity_id::text,
 e.alias_kind,e.alias_value,e.source_ref,e.sender_serial,e.observed_at,
 CASE WHEN octet_length(e.icmp_measurement::text)<=` + sizeParameter + ` THEN e.icmp_measurement END,
 statement_timestamp(),
 LEAST(COALESCE(e.expires_at,'infinity'),COALESCE(sender.not_after,'epoch'),
       COALESCE(m.expires_at,'infinity'),COALESCE(a.expires_at,'infinity')),
 EXISTS(SELECT 1 FROM entity_evidence other
   WHERE (other.tenant_id,other.context_id,other.agent_id,other.source_kind,other.configured_ref,other.observed_at)=
         (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref,e.observed_at)
     AND ROW(other.entity_id,other.alias_kind,other.alias_value,other.source_ref,other.sender_serial,other.icmp_measurement)
         IS DISTINCT FROM ROW(e.entity_id,e.alias_kind,e.alias_value,e.source_ref,e.sender_serial,e.icmp_measurement)),
 COALESCE(` + currentDirectICMPSourceSQL + `
   AND e.entity_id=` + entityParameter + ` AND e.source_ref='icmp:configured-test'
   AND e.alias_kind='address' AND e.icmp_measurement IS NOT NULL
   AND m.anchor_entity_id=e.entity_id
   AND EXISTS(SELECT 1 FROM entities node
     WHERE (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id)
       AND node.kind='device')
   AND t.enabled AND t.type='icmp' AND p.test_id IS NOT NULL AND c.test_id IS NOT NULL
   AND NOT (epoch.invalidating OR epoch.observation_erasing)
   AND (e.icmp_measurement->>'started_at')::timestamptz>=epoch.observation_not_before
   AND (e.icmp_measurement->>'started_at')::timestamptz>=m.assigned_at
   AND (e.icmp_measurement->>'started_at')::timestamptz>=a.assigned_at
   AND (e.icmp_measurement->>'started_at')::timestamptz>=sender.issued_at,false),
 COALESCE(t.id::text,''),COALESCE(t.type,''),COALESCE(t.target,''),
 COALESCE(t.interval_seconds,0),COALESCE(t.timeout_seconds,0),
 CASE WHEN octet_length(t.params::text)<=` + sizeParameter + ` THEN t.params END,
 COALESCE(t.updated_at,'epoch'),COALESCE(p.path_target,''),
 COALESCE(p.assigned_at,'epoch'),COALESCE(c.assigned_at,'epoch')`
}

func currentICMPLatestSQL(agentParameter, sourceParameter string) string {
	return `(SELECT * FROM entity_evidence
       WHERE tenant_id=$1 AND context_id=$2 AND agent_id=` + agentParameter + `
         AND source_kind='path_agent' AND configured_ref=` + sourceParameter + `
       ORDER BY observed_at DESC,id LIMIT 1)`
}

func currentICMPHealthJoinsSQL(agentParameter, sourceParameter string) string {
	return `
 LEFT JOIN entity_source_contexts m ON
   m.tenant_id=$1 AND m.context_id=$2 AND m.agent_id=` + agentParameter + `
   AND m.source_kind='path_agent' AND m.source_ref=` + sourceParameter + `
 LEFT JOIN entity_agent_contexts a ON
   a.tenant_id=$1 AND a.context_id=$2 AND a.agent_id=` + agentParameter + `
 LEFT JOIN agent_identities sender ON
   sender.tenant_id=$1 AND sender.agent_id=` + agentParameter + ` AND sender.serial=e.sender_serial
 LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=$1
 LEFT JOIN tests t ON t.tenant_id=$1 AND t.id=` + sourceParameter + `::uuid
 LEFT JOIN entity_path_test_contexts p ON
   p.tenant_id=$1 AND p.test_id=` + sourceParameter + `::uuid AND p.context_id=$2
 LEFT JOIN entity_test_contexts c ON
   c.tenant_id=$1 AND c.test_id=` + sourceParameter + `::uuid AND c.context_id=$2`
}

// This reader already joins the exact source, agent assignment and issued
// sender. ICMP requires its device anchor directly, with no inferred support
// or physical-neighbor alias. Reuse those joins instead of planning the
// registry's unreachable BMP/inferred-link subqueries for every source.
// All current-source, revocation and original observation clocks remain here.
const currentDirectICMPSourceSQL = `
 e.source_kind='path_agent' AND e.support_evidence_id IS NULL
 AND (e.bmp_peer_session IS NULL OR e.bmp_peer_session->>'state'='up')
 AND e.observed_at<=statement_timestamp()
 AND (e.expires_at IS NULL OR e.expires_at>statement_timestamp())
 AND m.anchor_entity_id=e.entity_id
 AND m.assigned_at<=statement_timestamp() AND m.assigned_at<=e.observed_at
 AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
 AND a.assigned_at<=statement_timestamp() AND a.assigned_at<=e.observed_at
 AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
 AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
   WHERE revoked.tenant_id=e.tenant_id AND revoked.agent_id=e.agent_id
     AND revoked.revoked_at IS NOT NULL
     AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
 AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
 AND sender.revoked_at IS NULL AND sender.issued_at<=e.observed_at
 AND sender.not_after>statement_timestamp()`

type icmpHealthRecord struct {
	out                                                                   ICMPHealth
	body, params                                                          []byte
	observedEntity, aliasKind, profileID, profileType, target, pathTarget string
	current, conflict                                                     bool
	updated, pathAssigned, contextAssigned, until                         time.Time
	test                                                                  testspec.ExecutableDefinition
}

func (record *icmpHealthRecord) scan(row interface{ Scan(...any) error }, ordinal *int64) error {
	destinations := []any{&record.out.EvidenceID, &record.out.Observation.ID, &record.observedEntity, &record.aliasKind,
		&record.out.Observation.Alias.Value, &record.out.Observation.SourceRef, &record.out.SenderSerial,
		&record.out.Observation.ObservedAt, &record.body, &record.out.AsOf, &record.until, &record.conflict, &record.current,
		&record.profileID, &record.profileType, &record.target, &record.test.IntervalSeconds, &record.test.TimeoutSeconds,
		&record.params, &record.updated, &record.pathTarget, &record.pathAssigned, &record.contextAssigned}
	if ordinal != nil {
		destinations = append([]any{ordinal}, destinations...)
	}
	return row.Scan(destinations...)
}

func scanICMPHealth(row pgx.Row, key entity.SourceKey, entityID string, freshness time.Duration) (ICMPHealth, error) {
	var record icmpHealthRecord
	err := record.scan(row, nil)
	if errors.Is(err, pgx.ErrNoRows) {
		return ICMPHealth{State: "unknown", Reason: "unavailable"}, nil
	}
	if err != nil {
		return ICMPHealth{}, err
	}
	return record.health(key, entityID, freshness)
}

func (record *icmpHealthRecord) health(key entity.SourceKey, entityID string, freshness time.Duration) (ICMPHealth, error) {
	unknown := ICMPHealth{State: "unknown", Reason: "unavailable"}
	record.out.Observation.Source = key
	if record.conflict {
		unknown.Reason = "conflicting measurements"
		return unknown, nil
	}
	if !record.current || record.observedEntity != entityID {
		return unknown, nil
	}
	if len(record.body) == 0 || len(record.params) == 0 {
		unknown.Reason = "source memory admission refused"
		return unknown, nil
	}
	record.out.Observation.Alias.Kind = entity.AliasKind(record.aliasKind)
	if err := json.Unmarshal(record.body, &record.out.Observation.ICMP); err != nil {
		return unknown, err
	}
	claim, err := record.out.Observation.Normalize(record.out.AsOf)
	if err != nil || claim.ICMP == nil {
		return unknown, entity.ErrInvalidClaim
	}
	record.test.ID, record.test.Type, record.test.Target = record.profileID, record.profileType, record.target
	if err := json.Unmarshal(record.params, &record.test.Params); err != nil {
		return unknown, err
	}
	matched, err := matchesICMPDefinition(claim, record.test, record.updated, record.pathTarget, record.pathAssigned, record.contextAssigned)
	if err != nil || !matched {
		return unknown, err
	}
	record.out.Observation = claim
	record.out.FreshUntil = claim.ObservedAt.Add(freshness)
	if record.until.Before(record.out.FreshUntil) {
		record.out.FreshUntil = record.until
	}
	if claim.ObservedAt.After(record.out.AsOf) || !record.out.FreshUntil.After(record.out.AsOf) {
		unknown.Reason = "stale measurement"
		return unknown, nil
	}
	m := claim.ICMP
	record.out.State, record.out.Reason = "unknown", "incomplete measurement"
	if m.Replies == 0 && len(m.NetworkErrors) != 0 {
		record.out.Reason = "current terminal network error is not router health"
		return record.out, nil
	}
	if m.Attempted == m.Requested && m.Transmitted == m.Requested && m.SendErrors == 0 && m.ReadComplete && !m.Canceled && !m.IOFailed {
		record.out.State, record.out.Reason = "up", "current complete echo replies"
		if m.Replies == 0 {
			record.out.State, record.out.Reason = "down", "current complete echo loss"
		}
	}
	return record.out, nil
}
