// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
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

const indexedICMPPopulationMinimum = 256

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
func (s *EntityRegistry) ReadICMPHealthPopulationInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, requests []ICMPHealthRequest, freshness time.Duration, maxBytes int64) (values []ICMPHealth, err error) {
	want, err := admittedEntityPopulation(ctx, sc, scope, len(requests), maxBytes)
	if err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil || freshness <= 0 {
		return nil, entity.ErrInvalidClaim
	}
	keys := make([]entity.SourceKey, len(requests))
	agents := make([]string, len(requests))
	sources := make([]string, len(requests))
	entities := make([]string, len(requests))
	remaining := maxBytes - int64(len(keys))*2048
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
		if err := chargeEntityPopulationInput(&remaining, key.AgentID, key.SourceRef, request.EntityID); err != nil {
			return nil, err
		}
		agents[i], sources[i], entities[i] = key.AgentID, key.SourceRef, request.EntityID
	}
	// A one-source graph needs no array plan. Keep it on the same exact-source
	// reader used to verify capture-time sender and current authority checks.
	if len(keys) == 1 {
		value, err := s.ReadICMPHealthInScope(ctx, sc, want, keys[0], requests[0].EntityID, freshness, maxBytes)
		if err != nil {
			return nil, err
		}
		return []ICMPHealth{value}, nil
	}
	if len(keys) >= indexedICMPPopulationMinimum {
		restore, planErr := preferIndexedICMPPopulation(ctx, sc.Q)
		if planErr != nil {
			return nil, planErr
		}
		defer func() {
			if restoreErr := restore(); restoreErr != nil {
				values, err = nil, errors.Join(err, restoreErr)
			}
		}()
	}
	query := currentICMPHealthPopulationSQL()
	// Replan this complete population; a cached generic plan cannot estimate
	// the current array lengths when rules have very different source counts.
	rows, err := sc.Q.Query(ctx, query, pgx.QueryExecModeDescribeExec, want.TenantID, want.ContextID, agents, sources, entities, maxBytes/int64(len(keys))/16, sources)
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

// A fresh tenant's relation estimates can lag its population. For the large
// batch, prefer the existing ordered exact-source index over a per-source sort
// and set joins over repeated dimension scans. Small reads retain point-plan
// preferences. These settings live on the caller's tenant transaction only
// until the rows close. A refusal to restore makes the whole read fail closed.
func preferIndexedICMPPopulation(ctx context.Context, q tenancy.Querier) (func() error, error) {
	var sortPlan, nestedLoop string
	if err := q.QueryRow(ctx, `SELECT current_setting('enable_sort'),current_setting('enable_nestloop')`).Scan(&sortPlan, &nestedLoop); err != nil {
		return nil, err
	}
	const configure = `SELECT set_config('enable_sort',$1,true),set_config('enable_nestloop',$2,true)`
	if _, err := q.Exec(ctx, configure, "off", "off"); err != nil {
		return nil, err
	}
	return func() error {
		_, err := q.Exec(ctx, configure, sortPlan, nestedLoop)
		return err
	}, nil
}

// ResolveAliasPopulationInScope preserves the single-alias resolver's current
// support and ambiguity rules for the complete population in the same scope.
func ResolveAliasPopulationInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, aliases []entity.AliasKey, maxBytes int64) (resolutions []entity.Resolution, err error) {
	want, err := admittedEntityPopulation(ctx, sc, scope, len(aliases), maxBytes)
	if err != nil {
		return nil, err
	}
	keys := make([]entity.AliasKey, len(aliases))
	kinds := make([]string, len(aliases))
	values := make([]string, len(aliases))
	configured := false
	remaining := maxBytes - int64(len(keys))*1024
	for i, alias := range aliases {
		key, err := alias.Normalize()
		if err != nil {
			return nil, err
		}
		if err := chargeEntityPopulationInput(&remaining, string(key.Kind), key.Value); err != nil {
			return nil, err
		}
		keys[i], kinds[i], values[i] = key, string(key.Kind), key.Value
		configured = configured || key.Kind == entity.ConfiguredTestAlias
	}
	// A fresh tenant can have thousands of evidence rows before statistics
	// represent them. Join the large request directly so a broad evidence plan
	// can scan the tenant once, instead of repeating its scan for every alias.
	setJoin := len(keys) >= 1024
	if setJoin {
		restore, planErr := preferPopulationSetJoin(ctx, sc.Q)
		if planErr != nil {
			return nil, planErr
		}
		defer func() {
			if restoreErr := restore(); restoreErr != nil {
				resolutions, err = nil, errors.Join(err, restoreErr)
			}
		}()
	}
	query := currentAliasPopulationSQL(configured, setJoin)
	rows, err := sc.Q.Query(ctx, query, pgx.QueryExecModeDescribeExec, want.TenantID, want.ContextID, kinds, values)
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

// Typed arrays expose the complete request count to PostgreSQL's planner;
// jsonb_array_elements otherwise estimates a fixed 100 rows for any population.
// Charge all encoded values before transfer, with fixed per-row admission above.
func chargeEntityPopulationInput(remaining *int64, values ...string) error {
	for _, value := range values {
		if *remaining < 0 || int64(len(value)) > *remaining/4 {
			return ErrAlertDependencyBudget
		}
		*remaining -= 4 * int64(len(value))
	}
	return nil
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
