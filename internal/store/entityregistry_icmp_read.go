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
func currentICMPHealthSQL() string {
	return `SELECT e.id::text,e.observation_id::text,e.entity_id::text,
 e.alias_kind,e.alias_value,e.source_ref,e.sender_serial,e.observed_at,
 CASE WHEN octet_length(e.icmp_measurement::text)<=$6 THEN e.icmp_measurement END,
 statement_timestamp(),
 LEAST(COALESCE(e.expires_at,'infinity'),COALESCE(sender.not_after,'epoch'),
       COALESCE(m.expires_at,'infinity'),COALESCE(a.expires_at,'infinity')),
 EXISTS(SELECT 1 FROM entity_evidence other
   WHERE (other.tenant_id,other.context_id,other.agent_id,other.source_kind,other.configured_ref,other.observed_at)=
         (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref,e.observed_at)
     AND ROW(other.entity_id,other.alias_kind,other.alias_value,other.source_ref,other.sender_serial,other.icmp_measurement)
         IS DISTINCT FROM ROW(e.entity_id,e.alias_kind,e.alias_value,e.source_ref,e.sender_serial,e.icmp_measurement)),
 COALESCE(` + currentEntityEvidenceSQL() + `
   AND e.entity_id=$5 AND e.source_ref='icmp:configured-test'
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
 CASE WHEN octet_length(t.params::text)<=$6 THEN t.params END,
 COALESCE(t.updated_at,'epoch'),COALESCE(p.path_target,''),
 COALESCE(p.assigned_at,'epoch'),COALESCE(c.assigned_at,'epoch')
 FROM (SELECT * FROM entity_evidence
       WHERE tenant_id=$1 AND context_id=$2 AND agent_id=$3
         AND source_kind='path_agent' AND configured_ref=$4
       ORDER BY observed_at DESC,id LIMIT 1) e
 LEFT JOIN entity_source_contexts m ON
   (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=
   (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
 LEFT JOIN entity_agent_contexts a ON
   (a.tenant_id,a.context_id,a.agent_id)=(e.tenant_id,e.context_id,e.agent_id)
 LEFT JOIN agent_identities sender ON
   (sender.tenant_id,sender.agent_id,sender.serial)=(e.tenant_id,e.agent_id,e.sender_serial)
 LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=e.tenant_id
 LEFT JOIN tests t ON (t.tenant_id,t.id::text)=(e.tenant_id,e.configured_ref)
 LEFT JOIN entity_path_test_contexts p ON
   (p.tenant_id,p.test_id,p.context_id)=(t.tenant_id,t.id,e.context_id)
 LEFT JOIN entity_test_contexts c ON
   (c.tenant_id,c.test_id,c.context_id)=(t.tenant_id,t.id,e.context_id)`
}

func scanICMPHealth(row pgx.Row, key entity.SourceKey, entityID string, freshness time.Duration) (ICMPHealth, error) {
	unknown := ICMPHealth{State: "unknown", Reason: "unavailable"}
	var out ICMPHealth
	var body, params []byte
	var observedEntity, aliasKind, profileID, profileType, target, pathTarget string
	var current, conflict bool
	var updated, pathAssigned, contextAssigned time.Time
	var until time.Time
	var test testspec.ExecutableDefinition
	out.Observation.Source = key
	err := row.Scan(&out.EvidenceID, &out.Observation.ID, &observedEntity, &aliasKind,
		&out.Observation.Alias.Value, &out.Observation.SourceRef, &out.SenderSerial,
		&out.Observation.ObservedAt, &body, &out.AsOf, &until, &conflict, &current,
		&profileID, &profileType, &target, &test.IntervalSeconds, &test.TimeoutSeconds,
		&params, &updated, &pathTarget, &pathAssigned, &contextAssigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	if conflict {
		unknown.Reason = "conflicting measurements"
		return unknown, nil
	}
	if !current || observedEntity != entityID {
		return unknown, nil
	}
	if len(body) == 0 || len(params) == 0 {
		unknown.Reason = "source memory admission refused"
		return unknown, nil
	}
	out.Observation.Alias.Kind = entity.AliasKind(aliasKind)
	if err := json.Unmarshal(body, &out.Observation.ICMP); err != nil {
		return unknown, err
	}
	claim, err := out.Observation.Normalize(out.AsOf)
	if err != nil || claim.ICMP == nil {
		return unknown, entity.ErrInvalidClaim
	}
	test.ID, test.Type, test.Target = profileID, profileType, target
	if err := json.Unmarshal(params, &test.Params); err != nil {
		return unknown, err
	}
	matched, err := matchesICMPDefinition(claim, test, updated, pathTarget, pathAssigned, contextAssigned)
	if err != nil || !matched {
		return unknown, err
	}
	out.Observation = claim
	out.FreshUntil = claim.ObservedAt.Add(freshness)
	if until.Before(out.FreshUntil) {
		out.FreshUntil = until
	}
	if claim.ObservedAt.After(out.AsOf) || !out.FreshUntil.After(out.AsOf) {
		unknown.Reason = "stale measurement"
		return unknown, nil
	}
	m := claim.ICMP
	out.State, out.Reason = "unknown", "incomplete measurement"
	if m.Attempted == m.Requested && m.Transmitted == m.Requested && m.SendErrors == 0 && m.ReadComplete && !m.Canceled && !m.IOFailed {
		out.State, out.Reason = "up", "current complete echo replies"
		if m.Replies == 0 {
			out.State, out.Reason = "down", "current complete echo loss"
		}
	}
	return out, nil
}
