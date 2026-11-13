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
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentPeerSessionMeasurement is an original point in a router's physical
// peer history. Current source authority is separate from peer-up identity.
// A reset, absent document or monitoring withdrawal never becomes a failure.
type IncidentPeerSessionMeasurement struct {
	TenantID, ContextID, RouterID, AgentID, ConfiguredRef string
	EvidenceID, ObservationID, SenderSerial, OriginSerial string
	AliasValue, SourceRef                                 string
	SourceGeneration                                      int64
	ObservedAt                                            time.Time
	ValidUntil                                            *time.Time
	SourceCurrent                                         bool
	Session                                               *entity.BMPPeerSession
	CaptureDigest                                         [32]byte
}

// PeerSessionMeasurementsInScope reads complete history only for routers whose
// incident interface sources were reauthorized in this same tenant snapshot.
// Missing or withdrawn source authority remains an explicit unavailable row.
func (Incidents) PeerSessionMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentInterfaceStateSource, from, to time.Time, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) ([]IncidentPeerSessionMeasurement, error) {
	if !to.After(from) {
		return nil, entity.ErrInvalidClaim
	}
	generation, err := recheckInterfaceStateSources(ctx, sc, sources, maxBytes, authorize)
	if err != nil {
		return nil, err
	}
	contexts, routers := []string{}, []string{}
	seen := map[string]bool{}
	for _, source := range sources {
		key := source.ContextID + ":" + source.RouterID
		if source.Current && !seen[key] {
			seen[key] = true
			contexts, routers = append(contexts, source.ContextID), append(routers, source.RouterID)
		}
	}
	fromSQL, toSQL := incidentMeasurementSQLWindow(from, to)
	remaining := maxBytes / 2
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS r(context_id,router_id))
 SELECT `+incidentPeerSessionColumns()+`
 FROM requested r JOIN entity_evidence e ON
 (e.tenant_id,e.context_id,e.entity_id)=($1,r.context_id,r.router_id)
 `+incidentPeerSessionAuthorityJoins()+`
 WHERE e.tenant_id=$1 AND e.source_kind='bmp_peer' AND e.alias_kind='bmp_peer_id'
 AND e.support_evidence_id IS NULL AND e.observed_at>=$4 AND e.observed_at<$5
 ORDER BY e.context_id,e.entity_id,e.observed_at,e.id LIMIT $7`, pgx.QueryExecModeDescribeExec,
		sc.Tenant.String(), contexts, routers, fromSQL, toSQL, remaining/8, remaining/2048+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IncidentPeerSessionMeasurement{}
	for rows.Next() {
		item, err := scanIncidentPeerSession(ctx, rows, sc.Tenant.String(), generation, &remaining)
		if err != nil {
			return nil, err
		}
		// SQL rounds only for an indexed superset. Keep the exact selected
		// interval at the original retained point, without changing its clock.
		if !item.ObservedAt.Before(from) && item.ObservedAt.Before(to) {
			out = append(out, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

// RecheckPeerSessionMeasurementsInScope selects only original compound IDs.
// New observations cannot replace a document already cited by a verdict.
func (Incidents) RecheckPeerSessionMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentInterfaceStateSource, original []IncidentPeerSessionMeasurement, maxBytes int64,
	authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) error {
	generation, err := recheckInterfaceStateSources(ctx, sc, sources, maxBytes, authorize)
	if err != nil {
		return err
	}
	if int64(len(original)) > maxBytes/2048 {
		return ErrIncidentImpactBudget
	}
	contexts, ids, routers := []string{}, []string{}, []string{}
	wanted := map[string][32]byte{}
	cohort := map[string]bool{}
	for _, source := range sources {
		if source.Current {
			cohort[source.ContextID+":"+source.RouterID] = true
		}
	}
	for _, item := range original {
		if item.TenantID != sc.Tenant.String() || item.SourceGeneration != generation || !cohort[item.ContextID+":"+item.RouterID] {
			return entity.ErrScopeMismatch
		}
		for _, id := range []string{item.ContextID, item.EvidenceID, item.RouterID} {
			if _, err := validRegistryUUID(id); err != nil {
				return err
			}
		}
		key := item.ContextID + ":" + item.EvidenceID
		if _, duplicate := wanted[key]; duplicate || item.CaptureDigest == ([32]byte{}) {
			return entity.ErrConflictingEvidence
		}
		wanted[key] = item.CaptureDigest
		contexts, ids, routers = append(contexts, item.ContextID), append(ids, item.EvidenceID), append(routers, item.RouterID)
	}
	remaining := maxBytes / 2
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::uuid[],$3::uuid[],$4::uuid[]) AS r(context_id,id,router_id))
 SELECT `+strings.ReplaceAll(incidentPeerSessionColumns(), "$6", "$5")+`
 FROM requested r JOIN entity_evidence e ON
 (e.tenant_id,e.context_id,e.id,e.entity_id)=($1,r.context_id,r.id,r.router_id)
 `+incidentPeerSessionAuthorityJoins()+`
 WHERE e.tenant_id=$1 AND e.source_kind='bmp_peer' AND e.alias_kind='bmp_peer_id'
 AND e.support_evidence_id IS NULL`, pgx.QueryExecModeDescribeExec, sc.Tenant.String(), contexts, ids, routers,
		// The recheck uses $5 for its original-document admission.
		remaining/8)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		item, err := scanIncidentPeerSession(ctx, rows, sc.Tenant.String(), generation, &remaining)
		if err != nil {
			return err
		}
		if wanted[item.ContextID+":"+item.EvidenceID] != item.CaptureDigest {
			return entity.ErrConflictingEvidence
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(wanted) {
		return entity.ErrConflictingEvidence
	}
	return ctx.Err()
}

func incidentPeerSessionColumns() string {
	return `e.context_id::text,e.entity_id::text,e.agent_id,e.configured_ref,
 e.id::text,e.observation_id::text,COALESCE(e.sender_serial,''),COALESCE(e.origin_serial,''),
 e.alias_value,e.source_ref,e.observed_at,` + interfaceRoleEvidenceExpirySQL() + `,
 COALESCE(` + strings.ReplaceAll(currentEntityEvidenceSourceSQL(false), "statement_timestamp()", "transaction_timestamp()") + `,false),
 CASE WHEN octet_length(e.bmp_peer_session::text)<=$6 THEN e.bmp_peer_session END,
 COALESCE(octet_length(e.bmp_peer_session::text),0)`
}

func scanIncidentPeerSession(ctx context.Context, row interface{ Scan(...any) error }, tenant string, generation int64, remaining *int64) (IncidentPeerSessionMeasurement, error) {
	item := IncidentPeerSessionMeasurement{TenantID: tenant, SourceGeneration: generation}
	var body []byte
	var size int64
	if err := row.Scan(&item.ContextID, &item.RouterID, &item.AgentID, &item.ConfiguredRef, &item.EvidenceID, &item.ObservationID, &item.SenderSerial, &item.OriginSerial,
		&item.AliasValue, &item.SourceRef, &item.ObservedAt, &item.ValidUntil, &item.SourceCurrent, &body, &size); err != nil {
		return item, err
	}
	cost := int64(2048+len(item.AgentID)+len(item.ConfiguredRef)+len(item.AliasValue)+len(item.SourceRef)) + 8*int64(len(body))
	if size > 0 && len(body) == 0 || cost > *remaining {
		return item, ErrIncidentImpactBudget
	}
	*remaining -= cost
	item.ObservedAt = item.ObservedAt.UTC()
	document, err := json.Marshal(struct {
		Header   IncidentPeerSessionMeasurement
		Document json.RawMessage
	}{item, body})
	if err != nil {
		return item, err
	}
	copy(item.CaptureDigest[:], crypto.Hash(document))
	if len(body) == 0 || !item.SourceCurrent {
		return item, ctx.Err()
	}
	var fact entity.BMPPeerSession
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fact); err != nil {
		return item, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return item, entity.ErrInvalidClaim
	}
	decoded, err := bgp.DecodePhysicalPeerSession(ctx, fact.RawFrame, bgp.PeerMessageBudget{MemoryBytes: int64(len(fact.RawFrame)) * 128, WorkUnits: int64(len(fact.RawFrame)) * 4})
	if err != nil || !reflect.DeepEqual(decoded, &fact) {
		return item, entity.ErrInvalidClaim
	}
	claim, err := (entity.Observation{ID: item.ObservationID, Source: entity.SourceKey{AgentID: item.AgentID, Kind: entity.BMPPeer, SourceRef: item.ConfiguredRef}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: item.AliasValue}, SourceRef: item.SourceRef, OriginSerial: item.OriginSerial, ObservedAt: item.ObservedAt, BMPPeerSession: &fact}).Normalize(item.ObservedAt)
	if err != nil {
		return item, err
	}
	item.Session = claim.BMPPeerSession
	return item, ctx.Err()
}

func incidentPeerSessionAuthorityJoins() string {
	joins := strings.ReplaceAll(interfaceRoleAuthorityJoinsSQL(), "\n JOIN ", "\n LEFT JOIN ")
	return strings.Replace(joins, " JOIN ", " LEFT JOIN ", 1)
}
