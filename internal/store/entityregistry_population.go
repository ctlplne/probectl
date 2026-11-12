// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ICMPHealthRequest names one exact configured source and canonical anchor.
// It supplies no authority; every row still checks current storage.
type ICMPHealthRequest struct {
	Source   entity.SourceKey
	EntityID string
}

func admittedEntityPopulation(ctx context.Context, sc tenancy.Scope, scope entity.Scope, count int, maxBytes int64) (entity.Scope, error) {
	bound, ok := tenancy.FromContext(ctx)
	want, err := scope.Normalize()
	if !ok || err != nil || bound != sc.Tenant || want.TenantID != bound.String() || sc.Q == nil {
		return entity.Scope{}, entity.ErrScopeMismatch
	}
	if count <= 0 || int64(count) > maxBytes/4096 {
		return entity.Scope{}, ErrAlertDependencyBudget
	}
	if err := ctx.Err(); err != nil {
		return entity.Scope{}, err
	}
	return want, nil
}

// ReadICMPHealthPopulationInScope plans one set query for every exact source in the
// caller's existing transaction. No extra connection, broader query, source
// fallback or result prefix is introduced. The SQL and decoder are shared
// with the single-source reader, including latest-unknown/conflict semantics.
func (s *EntityRegistry) ReadICMPHealthPopulationInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, requests []ICMPHealthRequest, freshness time.Duration, maxBytes int64) ([]ICMPHealth, error) {
	want, err := admittedEntityPopulation(ctx, sc, scope, len(requests), maxBytes)
	if err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil || freshness <= 0 {
		return nil, entity.ErrInvalidClaim
	}
	keys := make([]entity.SourceKey, len(requests))
	type reference struct {
		AgentID   string `json:"agent_id"`
		SourceRef string `json:"source_ref"`
		EntityID  string `json:"entity_id"`
	}
	references := make([]reference, len(requests))
	for i, request := range requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := request.Source.Normalize()
		if err != nil || key.Kind != entity.PathAgent {
			return nil, entity.ErrInvalidClaim
		}
		if _, err := validRegistryUUID(key.SourceRef); err != nil {
			return nil, err
		}
		if _, err := validRegistryUUID(request.EntityID); err != nil {
			return nil, err
		}
		keys[i] = key
		references[i] = reference{AgentID: key.AgentID, SourceRef: key.SourceRef, EntityID: request.EntityID}
	}
	body, err := json.Marshal(references)
	if err != nil {
		return nil, err
	}
	if int64(len(body))*4 > maxBytes-int64(len(keys))*2048 {
		return nil, ErrAlertDependencyBudget
	}
	query := `WITH requested AS (
 SELECT ordinality,value->>'agent_id' AS agent_id,value->>'source_ref' AS source_ref,(value->>'entity_id')::uuid AS entity_id
 FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS input(value,ordinality)
 ) SELECT requested.ordinality,measured.* FROM requested JOIN LATERAL (` + currentICMPHealthSQL(true) + `) AS measured ON true ORDER BY requested.ordinality`
	rows, err := sc.Q.Query(ctx, query, want.TenantID, want.ContextID, body, maxBytes/int64(len(keys))/16)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ICMPHealth, len(keys))
	seen := make([]bool, len(keys))
	for i := range out {
		out[i] = ICMPHealth{State: "unknown", Reason: "unavailable"}
	}
	for rows.Next() {
		var ordinal int64
		var record icmpHealthRecord
		if err := record.scan(rows, &ordinal); err != nil {
			return nil, err
		}
		if ordinal <= 0 || ordinal > int64(len(keys)) || seen[ordinal-1] {
			return nil, entity.ErrInvalidClaim
		}
		index := int(ordinal - 1)
		value, err := record.health(keys[index], requests[index].EntityID, freshness)
		if err != nil {
			return nil, err
		}
		out[index] = value
		seen[index] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ResolveAliasPopulationInScope preserves the single-alias resolver's current
// support and ambiguity rules for the complete population in the same scope.
func ResolveAliasPopulationInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, aliases []entity.AliasKey, maxBytes int64) ([]entity.Resolution, error) {
	want, err := admittedEntityPopulation(ctx, sc, scope, len(aliases), maxBytes)
	if err != nil {
		return nil, err
	}
	keys := make([]entity.AliasKey, len(aliases))
	type reference struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	references := make([]reference, len(aliases))
	for i, alias := range aliases {
		key, err := alias.Normalize()
		if err != nil {
			return nil, err
		}
		if int64(len(key.Value)) > (maxBytes/int64(len(aliases))-2048)/4 {
			return nil, ErrAlertDependencyBudget
		}
		keys[i] = key
		references[i] = reference{Kind: string(key.Kind), Value: key.Value}
	}
	body, err := json.Marshal(references)
	if err != nil {
		return nil, err
	}
	remaining := maxBytes - int64(len(keys))*1024 - int64(len(body))*4
	if remaining < 0 {
		return nil, ErrAlertDependencyBudget
	}
	query := `WITH requested AS (
 SELECT value->>'kind' AS kind,value->>'value' AS alias_value,ordinality
 FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS input(value,ordinality)
 ) SELECT requested.ordinality,resolved.* FROM requested
 JOIN LATERAL (` + currentAliasResolutionSQL(true) + `) AS resolved(
 evidence_id,entity_id,entity_kind,source,source_ref,agent_id,source_kind,configured_ref,observed_at,support_evidence_id) ON true
 ORDER BY requested.ordinality,resolved.entity_id`
	rows, err := sc.Q.Query(ctx, query, want.TenantID, want.ContextID, body)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	claims := make([][]entity.Claim, len(keys))
	for rows.Next() {
		index, claim, err := scanPopulationAliasRow(rows, want, keys, &remaining)
		if err != nil {
			return nil, err
		}
		if len(claims[index]) >= 4 {
			return nil, entity.ErrInvalidClaim
		}
		claims[index] = append(claims[index], claim)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]entity.Resolution, len(keys))
	for i, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, err := resolveAliasClaims(want, key, claims[i])
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	return out, nil
}

func scanPopulationAliasRow(rows pgx.Rows, want entity.Scope, keys []entity.AliasKey, remaining *int64) (int, entity.Claim, error) {
	var ordinal int64
	var claim entity.Claim
	var kind, sourceKind string
	err := rows.Scan(&ordinal, &claim.EvidenceID, &claim.EntityID, &kind, &claim.Source, &claim.SourceRef, &claim.SourceKey.AgentID, &sourceKind, &claim.SourceKey.SourceRef, &claim.ObservedAt, &claim.SupportEvidenceID)
	if err != nil {
		return 0, entity.Claim{}, err
	}
	if ordinal <= 0 || ordinal > int64(len(keys)) {
		return 0, entity.Claim{}, entity.ErrInvalidClaim
	}
	charge := int64(512)
	for _, value := range []string{claim.EvidenceID, claim.EntityID, kind, claim.Source, claim.SourceRef, claim.SourceKey.AgentID, sourceKind, claim.SourceKey.SourceRef, claim.SupportEvidenceID} {
		charge += int64(len(value)) * 4
	}
	if charge > *remaining {
		return 0, entity.Claim{}, ErrAlertDependencyBudget
	}
	*remaining -= charge
	index := int(ordinal - 1)
	claim.Scope, claim.Alias = want, keys[index]
	claim.EntityKind = entity.Kind(kind)
	claim.SourceKey.Kind = entity.SourceKind(sourceKind)
	return index, claim, nil
}
