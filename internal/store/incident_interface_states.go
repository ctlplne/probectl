// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentInterfaceStateMeasurement is an original retained point, not a
// carried-forward current state. An absent document remains an unavailable
// point; later readers cannot fill that gap with an earlier up/down sample.
type IncidentInterfaceStateMeasurement struct {
	TenantID, ContextID, EntityID, AgentID, ConfiguredRef string
	EvidenceID, ObservationID, SenderSerial, SourceRef    string
	AliasValue                                            string
	SourceGeneration                                      int64
	IfIndex                                               uint32
	ObservedAt                                            time.Time
	OriginalSenderValid                                   bool
	CaptureDigest                                         [32]byte
	Available                                             bool
	Reason                                                string
	State                                                 *entity.SNMPInterfaceState
}

// InterfaceStateMeasurementsInScope keeps the complete selected history and
// its explicit unavailable points. It reauthorizes and reloads each selected
// current source in this snapshot; callers must still recheck complete incident
// membership, current actor/source policy and these original IDs at publication.
func (Incidents) InterfaceStateMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentInterfaceStateSource, from, to time.Time, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) ([]IncidentInterfaceStateMeasurement, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if !to.After(from) {
		return nil, entity.ErrInvalidClaim
	}
	generation, err := recheckInterfaceStateSources(ctx, sc, sources, maxBytes, authorize)
	if err != nil {
		return nil, err
	}
	contexts, entities, agents, refs, indices := []string{}, []string{}, []string{}, []string{}, []string{}
	since := []time.Time{}
	for _, source := range sources {
		if !source.Current {
			continue
		}
		contexts, entities = append(contexts, source.ContextID), append(entities, source.EntityID)
		agents, refs = append(agents, source.AgentID), append(refs, source.ConfiguredRef)
		indices, since = append(indices, strconv.FormatUint(uint64(source.IfIndex), 10)), append(since, source.CurrentSince)
	}
	sqlFrom, sqlTo := incidentMeasurementSQLWindow(from, to)
	remaining := maxBytes / 2
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[],$4::text[],$5::text[],$6::text[],$7::timestamptz[])
 AS r(context_id,entity_id,agent_id,configured_ref,if_index,current_since))
 SELECT `+strings.ReplaceAll(incidentInterfaceStateColumns, "$BODY_LIMIT", "$10")+`
 FROM requested r JOIN entity_evidence e ON e.tenant_id=$1 AND e.context_id=r.context_id AND e.entity_id=r.entity_id
 AND e.agent_id=r.agent_id AND e.source_kind='device_target' AND e.configured_ref=r.configured_ref
 AND e.alias_kind='snmp_interface_id' AND e.alias_value=r.if_index AND e.source_ref='snmp:ifIndex:'||r.if_index
 LEFT JOIN agent_identities sender ON sender.tenant_id=$1 AND sender.agent_id=e.agent_id AND sender.serial=e.sender_serial
 WHERE e.tenant_id=$1 AND e.observed_at>=r.current_since AND e.observed_at>=$8 AND e.observed_at<$9
 ORDER BY e.context_id,e.entity_id,e.observed_at,e.id LIMIT $11`, pgx.QueryExecModeDescribeExec,
		sc.Tenant.String(), contexts, entities, agents, refs, indices, since, sqlFrom, sqlTo, remaining/8, remaining/1024+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IncidentInterfaceStateMeasurement{}
	for rows.Next() {
		item, body, err := scanIncidentInterfaceState(rows, sc.Tenant.String(), generation, &remaining)
		if err != nil {
			return nil, err
		}
		item.Reason = "unavailable_original_interface_state"
		if item.OriginalSenderValid && len(body) != 0 {
			var state entity.SNMPInterfaceState
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&state); err != nil {
				return nil, err
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				return nil, entity.ErrInvalidClaim
			}
			claim, err := (entity.Observation{ID: item.ObservationID,
				Source:    entity.SourceKey{AgentID: item.AgentID, Kind: entity.DeviceTarget, SourceRef: item.ConfiguredRef},
				Alias:     entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: strconv.FormatUint(uint64(item.IfIndex), 10)},
				SourceRef: item.SourceRef, ObservedAt: item.ObservedAt, SNMPInterfaceState: &state}).Normalize(item.ObservedAt)
			if err != nil {
				return nil, err
			}
			item.State, item.Available, item.Reason = claim.SNMPInterfaceState, true, "original_attested_interface_state"
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

// RecheckInterfaceStateMeasurementsInScope reads only original selectors. New
// polls cannot replace the captured documents or force a new history query.
func (Incidents) RecheckInterfaceStateMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentInterfaceStateSource, reads []IncidentInterfaceStateMeasurement, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	for _, read := range reads {
		if read.TenantID != bound.String() {
			return entity.ErrScopeMismatch
		}
	}
	generation, err := recheckInterfaceStateSources(ctx, sc, sources, maxBytes, authorize)
	if err != nil {
		return err
	}
	if int64(len(reads)) > maxBytes/2048 {
		return ErrIncidentImpactBudget
	}
	contexts, ids, entities, agents, refs, indices := []string{}, []string{}, []string{}, []string{}, []string{}, []string{}
	since := []time.Time{}
	selected := map[string]IncidentInterfaceStateSource{}
	for _, source := range sources {
		selected[source.ContextID+":"+source.EntityID] = source
	}
	wanted := map[string][32]byte{}
	for _, read := range reads {
		if read.SourceGeneration != generation {
			return sourceepoch.ErrInvalidating
		}
		source, found := selected[read.ContextID+":"+read.EntityID]
		if !found || source.AgentID != read.AgentID || source.ConfiguredRef != read.ConfiguredRef || source.IfIndex != read.IfIndex {
			return entity.ErrScopeMismatch
		}
		if !source.Current || read.ObservedAt.Before(source.CurrentSince) {
			return sourceepoch.ErrInvalidating
		}
		for _, id := range []string{read.ContextID, read.EvidenceID} {
			if _, err := validRegistryUUID(id); err != nil {
				return err
			}
		}
		key := read.ContextID + ":" + read.EvidenceID
		if _, duplicate := wanted[key]; duplicate || read.CaptureDigest == ([32]byte{}) {
			return entity.ErrConflictingEvidence
		}
		wanted[key] = read.CaptureDigest
		contexts, ids = append(contexts, read.ContextID), append(ids, read.EvidenceID)
		entities, agents, refs = append(entities, source.EntityID), append(agents, source.AgentID), append(refs, source.ConfiguredRef)
		indices, since = append(indices, strconv.FormatUint(uint64(source.IfIndex), 10)), append(since, source.CurrentSince)
	}
	remaining := maxBytes / 2
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[],$4::uuid[],$5::text[],$6::text[],$7::text[],$8::timestamptz[])
 AS r(context_id,id,entity_id,agent_id,configured_ref,if_index,current_since))
 SELECT `+strings.ReplaceAll(incidentInterfaceStateColumns, "$BODY_LIMIT", "$9")+`
 FROM requested r JOIN entity_evidence e ON (e.tenant_id,e.context_id,e.id)=($1,r.context_id,r.id)
 AND e.entity_id=r.entity_id AND e.agent_id=r.agent_id AND e.configured_ref=r.configured_ref
 AND e.alias_value=r.if_index AND e.observed_at>=r.current_since
 LEFT JOIN agent_identities sender ON sender.tenant_id=$1 AND sender.agent_id=e.agent_id AND sender.serial=e.sender_serial
 WHERE e.tenant_id=$1 AND e.source_kind='device_target' AND e.alias_kind='snmp_interface_id'`, pgx.QueryExecModeDescribeExec,
		sc.Tenant.String(), contexts, ids, entities, agents, refs, indices, since, remaining/8)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		item, _, err := scanIncidentInterfaceState(rows, sc.Tenant.String(), generation, &remaining)
		if err != nil {
			return err
		}
		if wanted[item.ContextID+":"+item.EvidenceID] != item.CaptureDigest {
			return entity.ErrConflictingEvidence
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != len(wanted) {
		return entity.ErrConflictingEvidence
	}
	return ctx.Err()
}

// $BODY_LIMIT is replaced only by the fixed positional parameter number of
// these two internal queries; no request data enters SQL text.
const incidentInterfaceStateColumns = `e.context_id::text,e.entity_id::text,e.agent_id,e.configured_ref,
 e.id::text,e.observation_id::text,COALESCE(e.sender_serial,''),e.source_ref,e.alias_value,e.observed_at,
 CASE WHEN octet_length(e.snmp_interface_state::text)<=$BODY_LIMIT THEN e.snmp_interface_state END,
 COALESCE(octet_length(e.snmp_interface_state::text),0),
 COALESCE(sender.revoked_at IS NULL AND sender.serial=e.sender_serial
 AND sender.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/entity/'||e.agent_id
 AND sender.issued_at<=e.observed_at AND sender.not_after>e.observed_at,false)`

func scanIncidentInterfaceState(row interface{ Scan(...any) error }, tenant string, generation int64, remaining *int64) (IncidentInterfaceStateMeasurement, []byte, error) {
	item := IncidentInterfaceStateMeasurement{TenantID: tenant, SourceGeneration: generation}
	var body []byte
	var size int64
	var index string
	if err := row.Scan(&item.ContextID, &item.EntityID, &item.AgentID, &item.ConfiguredRef, &item.EvidenceID, &item.ObservationID,
		&item.SenderSerial, &item.SourceRef, &index, &item.ObservedAt, &body, &size, &item.OriginalSenderValid); err != nil {
		return item, nil, err
	}
	parsed, err := strconv.ParseUint(index, 10, 32)
	if err != nil || parsed == 0 {
		return item, nil, entity.ErrInvalidClaim
	}
	item.IfIndex = uint32(parsed)
	item.AliasValue, item.ObservedAt = index, item.ObservedAt.UTC()
	cost := int64(2048+len(item.AgentID)+len(item.ConfiguredRef)+len(item.SenderSerial)) + 4*int64(len(body))
	if size > 0 && len(body) == 0 || cost > *remaining {
		return item, nil, ErrIncidentImpactBudget
	}
	*remaining -= cost
	document, err := json.Marshal(struct {
		Header   IncidentInterfaceStateMeasurement
		Document json.RawMessage
	}{item, body})
	if err != nil {
		return item, nil, err
	}
	copy(item.CaptureDigest[:], crypto.Hash(document))
	return item, body, nil
}

func recheckInterfaceStateSources(ctx context.Context, sc tenancy.Scope, sources []IncidentInterfaceStateSource, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) (int64, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || authorize == nil {
		return 0, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return 0, err
	}
	for _, source := range sources {
		if source.TenantID != bound.String() {
			return 0, entity.ErrScopeMismatch
		}
	}
	if maxBytes < 16<<10 || int64(len(sources)) > maxBytes/4096 {
		return 0, ErrIncidentImpactBudget
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return 0, err
	}
	inputs := &IncidentImpactInputs{TenantID: bound.String(), SourceGeneration: generation}
	seen := map[string]bool{}
	for _, source := range sources {
		if source.SourceGeneration != generation {
			return 0, sourceepoch.ErrInvalidating
		}
		key := source.ContextID + ":" + source.EntityID
		if seen[key] {
			return 0, entity.ErrConflictingEvidence
		}
		seen[key] = true
		inputs.Entities = append(inputs.Entities, IncidentImpactEntity{ContextID: source.ContextID, EntityID: source.EntityID})
	}
	current, err := (Incidents{}).InterfaceStateSourcesInScope(ctx, sc, inputs,
		entity.InterfaceRolePolicyBudget{MemoryBytes: maxBytes / 4, WorkUnits: maxBytes}, authorize)
	if err != nil {
		return 0, err
	}
	if len(current) != len(sources) {
		return 0, sourceepoch.ErrInvalidating
	}
	for i, source := range sources {
		got := current[i]
		sameUntil := source.ValidUntil == nil && got.ValidUntil == nil || source.ValidUntil != nil && got.ValidUntil != nil && source.ValidUntil.Equal(*got.ValidUntil)
		if source.ContextID != got.ContextID || source.EntityID != got.EntityID || source.RouterID != got.RouterID || source.AgentID != got.AgentID || source.ConfiguredRef != got.ConfiguredRef ||
			source.IfIndex != got.IfIndex || !source.CurrentSince.Equal(got.CurrentSince) || !sameUntil || source.Current != got.Current || source.Reason != got.Reason ||
			source.Current && (source.ValidUntil == nil || !source.ValidUntil.After(time.Now().UTC())) {
			return 0, sourceepoch.ErrInvalidating
		}
	}
	return generation, ctx.Err()
}
