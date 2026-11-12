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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentTestMeasurement is an operation-local retained observation. It is
// never a source grant. Current configured ownership, current sender authority
// and the original issued sender are independent checks. Expiry of a rotated
// original certificate does not rewrite an observation made during its valid
// interval; revocation and current source withdrawal still fail closed.
type IncidentTestMeasurement struct {
	TenantID                                string
	SourceGeneration                        int64
	ContextID, EntityID, TestID, AgentID    string
	EvidenceID, ObservationID, SenderSerial string
	Alias, SourceRef                        string
	ObservedAt                              time.Time
	CaptureDigest                           [32]byte
	Available                               bool
	Reason                                  string
	ICMP                                    *entity.ICMPMeasurement
}

type incidentImpactTestKey struct{ contextID, entityID, agentID, testID string }

// IncidentICMPMeasurementsInScope reads every retained typed observation in
// either selected comparison window. The OR selects overlapping ranges once;
// each period later counts its own complete population independently. It never
// scans the intervening week or a display/ranking prefix. Non-ICMP outcome
// evidence remains a separate, explicitly owed collector extension.
func (Incidents) IncidentICMPMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentConfiguredTest, from, to time.Time, maxBytes int64) ([]IncidentTestMeasurement, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if !to.After(from) || maxBytes < 4096 || int64(len(sources)) > maxBytes/1024 {
		return nil, ErrIncidentImpactBudget
	}
	for _, source := range sources {
		if source.TenantID != bound.String() {
			return nil, entity.ErrScopeMismatch
		}
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	var contexts, entities, agents, tests []string
	selected := map[incidentImpactTestKey]IncidentConfiguredTest{}
	for _, source := range sources {
		if source.SourceGeneration != generation {
			return nil, sourceepoch.ErrInvalidating
		}
		if source.Type != "icmp" {
			continue
		}
		for _, id := range []string{source.ContextID, source.EntityID, source.TestID} {
			if _, err := validRegistryUUID(id); err != nil {
				return nil, err
			}
		}
		key := incidentImpactTestKey{source.ContextID, source.EntityID, source.AgentID, source.TestID}
		if _, found := selected[key]; found {
			continue
		}
		selected[key] = source
		contexts = append(contexts, source.ContextID)
		entities = append(entities, source.EntityID)
		agents = append(agents, source.AgentID)
		tests = append(tests, source.TestID)
	}
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[],$4::text[],$5::text[]) AS r(context_id,entity_id,agent_id,test_id))
 SELECT e.context_id::text,e.entity_id::text,e.configured_ref,e.agent_id,e.id::text,e.observation_id::text,
 COALESCE(e.sender_serial,''),e.alias_value,e.source_ref,e.observed_at,
 CASE WHEN octet_length(e.icmp_measurement::text)<=$10 THEN e.icmp_measurement END,
 COALESCE(octet_length(e.icmp_measurement::text),0),
 COALESCE(sender.serial=e.sender_serial AND sender.revoked_at IS NULL
 AND sender.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/entity/'||e.agent_id
 AND sender.issued_at<=e.observed_at AND sender.not_after>e.observed_at,false),COALESCE(sender.issued_at,'epoch')
 FROM requested r JOIN entity_evidence e ON e.tenant_id=$1 AND e.context_id=r.context_id AND e.entity_id=r.entity_id
 AND e.agent_id=r.agent_id AND e.source_kind='path_agent' AND e.configured_ref=r.test_id
 LEFT JOIN agent_identities sender ON sender.tenant_id=$1 AND sender.agent_id=e.agent_id AND sender.serial=e.sender_serial
 WHERE e.tenant_id=$1 AND e.source_ref='icmp:configured-test' AND e.alias_kind='address'
 AND ((e.observed_at>=$6 AND e.observed_at<$7) OR (e.observed_at>=$8 AND e.observed_at<$9))
 ORDER BY e.context_id,e.entity_id,e.agent_id,e.configured_ref,e.observed_at,e.id LIMIT $11`, pgx.QueryExecModeDescribeExec, bound.String(), contexts, entities, agents, tests, from, to, from.Add(-7*24*time.Hour), to.Add(-7*24*time.Hour), maxBytes/8, maxBytes/1024+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IncidentTestMeasurement{}
	remaining := maxBytes - int64(len(selected))*512
	for rows.Next() {
		var item IncidentTestMeasurement
		var body []byte
		var size int64
		var senderValid bool
		var senderIssued time.Time
		if err := rows.Scan(&item.ContextID, &item.EntityID, &item.TestID, &item.AgentID, &item.EvidenceID, &item.ObservationID, &item.SenderSerial, &item.Alias, &item.SourceRef, &item.ObservedAt, &body, &size, &senderValid, &senderIssued); err != nil {
			return nil, err
		}
		cost := int64(1024+len(item.AgentID)+len(item.SenderSerial)+len(item.Alias)) + 4*int64(len(body))
		if size > 0 && len(body) == 0 || cost > remaining {
			return nil, ErrIncidentImpactBudget
		}
		remaining -= cost
		item.TenantID = bound.String()
		item.SourceGeneration = generation
		source, found := selected[incidentImpactTestKey{item.ContextID, item.EntityID, item.AgentID, item.TestID}]
		if !found {
			return nil, entity.ErrScopeMismatch
		}
		item.CaptureDigest, err = incidentTestCaptureDigest(item, body)
		if err != nil {
			return nil, err
		}
		if err := decodeIncidentICMPMeasurement(&item, source, body, senderValid, senderIssued); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

func incidentTestCaptureDigest(item IncidentTestMeasurement, body []byte) ([32]byte, error) {
	// Bind the immutable header and complete original document, rather than a
	// returned counter prefix or a client-supplied measurement fingerprint.
	item.CaptureDigest = [32]byte{}
	item.ICMP = nil
	item.Available = false
	item.Reason = ""
	data, err := json.Marshal(struct {
		Header   IncidentTestMeasurement
		Document json.RawMessage
	}{item, body})
	if err != nil {
		return [32]byte{}, err
	}
	var digest [32]byte
	copy(digest[:], crypto.Hash(data))
	return digest, nil
}

func decodeIncidentICMPMeasurement(item *IncidentTestMeasurement, source IncidentConfiguredTest, body []byte, senderValid bool, senderIssued time.Time) error {
	item.Reason = "unavailable_original_test_observation"
	if len(body) == 0 || !senderValid || source.MeasurementIdentityUntil == nil || !source.MeasurementIdentityUntil.After(time.Now().UTC()) {
		return nil
	}
	var measurement entity.ICMPMeasurement
	if err := json.Unmarshal(body, &measurement); err != nil {
		return err
	}
	if measurement.StartedAt.Before(senderIssued) || measurement.StartedAt.Before(source.CurrentSince) {
		return nil
	}
	claim := entity.Observation{ID: item.ObservationID, Source: entity.SourceKey{AgentID: item.AgentID, Kind: entity.PathAgent, SourceRef: item.TestID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: item.Alias}, SourceRef: item.SourceRef, ObservedAt: item.ObservedAt, ICMP: &measurement}
	// Normalize against the original receipt clock. Historical reads do not
	// mint a new receipt or pretend that a week-old sample is currently fresh.
	claim, err := claim.Normalize(item.ObservedAt)
	if errors.Is(err, entity.ErrInvalidClaim) {
		return nil
	}
	if err != nil {
		return err
	}
	matched, err := matchesICMPDefinition(claim, source.Definition, source.CurrentSince, path.TargetHost(source.Target), source.CurrentSince, source.CurrentSince)
	if err != nil {
		return err
	}
	if !matched {
		return nil
	}
	item.Available, item.Reason, item.ICMP = true, "original_attested_test_observation", claim.ICMP
	return nil
}

// RecheckIncidentTestMeasurementsInScope verifies that every original retained
// selector still exists unchanged in the final tenant/current-source snapshot.
// It reads original IDs only, not a second historical query or a reusable grant.
func (Incidents) RecheckIncidentTestMeasurementsInScope(ctx context.Context, sc tenancy.Scope, reads []IncidentTestMeasurement, maxBytes int64) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if maxBytes < 4096 || int64(len(reads)) > maxBytes/512 {
		return ErrIncidentImpactBudget
	}
	for _, read := range reads {
		if read.TenantID != bound.String() {
			return entity.ErrScopeMismatch
		}
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return err
	}
	var contexts, ids []string
	wanted := map[string][32]byte{}
	for _, read := range reads {
		if read.SourceGeneration != generation {
			return sourceepoch.ErrInvalidating
		}
		for _, id := range []string{read.ContextID, read.EvidenceID} {
			if _, err := validRegistryUUID(id); err != nil {
				return err
			}
		}
		key := read.ContextID + ":" + read.EvidenceID
		if old, found := wanted[key]; found {
			if old != read.CaptureDigest {
				return entity.ErrConflictingEvidence
			}
			continue
		}
		wanted[key] = read.CaptureDigest
		contexts = append(contexts, read.ContextID)
		ids = append(ids, read.EvidenceID)
	}
	rows, err := sc.Q.Query(ctx, `WITH requested AS (SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS r(context_id,id))
 SELECT e.context_id::text,e.entity_id::text,e.configured_ref,e.agent_id,e.id::text,e.observation_id::text,
 COALESCE(e.sender_serial,''),e.alias_value,e.source_ref,e.observed_at,
 CASE WHEN octet_length(e.icmp_measurement::text)<=$4 THEN e.icmp_measurement END,COALESCE(octet_length(e.icmp_measurement::text),0)
 FROM requested r JOIN entity_evidence e ON e.tenant_id=$1 AND e.context_id=r.context_id AND e.id=r.id
 WHERE e.tenant_id=$1 AND e.source_kind='path_agent' AND e.source_ref='icmp:configured-test' AND e.alias_kind='address'`, pgx.QueryExecModeDescribeExec, bound.String(), contexts, ids, maxBytes/8)
	if err != nil {
		return err
	}
	defer rows.Close()
	remaining := maxBytes - int64(len(wanted))*512
	for rows.Next() {
		var read IncidentTestMeasurement
		var body []byte
		var size int64
		if err := rows.Scan(&read.ContextID, &read.EntityID, &read.TestID, &read.AgentID, &read.EvidenceID, &read.ObservationID, &read.SenderSerial, &read.Alias, &read.SourceRef, &read.ObservedAt, &body, &size); err != nil {
			return err
		}
		read.TenantID = bound.String()
		read.SourceGeneration = generation
		cost := int64(512+len(read.AgentID)+len(read.Alias)+len(read.SenderSerial)) + 4*int64(len(body))
		if size > 0 && len(body) == 0 || cost > remaining {
			return ErrIncidentImpactBudget
		}
		remaining -= cost
		digest, err := incidentTestCaptureDigest(read, body)
		if err != nil {
			return err
		}
		key := read.ContextID + ":" + read.EvidenceID
		old, found := wanted[key]
		if !found || old != digest {
			return entity.ErrConflictingEvidence
		}
		delete(wanted, key)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(wanted) != 0 {
		return entity.ErrConflictingEvidence
	}
	return ctx.Err()
}
