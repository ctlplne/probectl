// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ICMPHealthRequest names one exact configured source and canonical anchor.
// It supplies no authority; every queued query still checks current storage.
type ICMPHealthRequest struct {
	Source   entity.SourceKey
	EntityID string
}

type tenantBatchReader interface {
	SendBatch(context.Context, *pgx.Batch) pgx.BatchResults
}

func admittedEntityPopulation(ctx context.Context, sc tenancy.Scope, scope entity.Scope, count int, maxBytes int64) (entity.Scope, tenantBatchReader, error) {
	bound, ok := tenancy.FromContext(ctx)
	want, err := scope.Normalize()
	if !ok || err != nil || bound != sc.Tenant || want.TenantID != bound.String() {
		return entity.Scope{}, nil, entity.ErrScopeMismatch
	}
	reader, ok := sc.Q.(tenantBatchReader)
	if !ok || count <= 0 || int64(count) > maxBytes/4096 {
		return entity.Scope{}, nil, ErrAlertDependencyBudget
	}
	if err := ctx.Err(); err != nil {
		return entity.Scope{}, nil, err
	}
	return want, reader, nil
}

// ReadICMPHealthPopulationInScope pipelines every exact-source read over the
// caller's existing transaction. No extra connection, broader query, source
// fallback or result prefix is introduced. The SQL and decoder are shared
// with the single-source reader, including latest-unknown/conflict semantics.
func (s *EntityRegistry) ReadICMPHealthPopulationInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, requests []ICMPHealthRequest, freshness time.Duration, maxBytes int64) ([]ICMPHealth, error) {
	want, reader, err := admittedEntityPopulation(ctx, sc, scope, len(requests), maxBytes)
	if err != nil {
		return nil, err
	}
	if s == nil || s.pool == nil || freshness <= 0 {
		return nil, entity.ErrInvalidClaim
	}
	perSource := maxBytes / int64(len(requests))
	keys := make([]entity.SourceKey, len(requests))
	batch := &pgx.Batch{}
	query := currentICMPHealthSQL()
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
		batch.Queue(query, want.TenantID, want.ContextID, key.AgentID, key.SourceRef, request.EntityID, perSource/16)
	}
	results := reader.SendBatch(ctx, batch)
	defer results.Close()
	out := make([]ICMPHealth, len(requests))
	for i, request := range requests {
		value, err := scanICMPHealth(results.QueryRow(), keys[i], request.EntityID, freshness)
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	if err := results.Close(); err != nil {
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
	want, reader, err := admittedEntityPopulation(ctx, sc, scope, len(aliases), maxBytes)
	if err != nil {
		return nil, err
	}
	keys := make([]entity.AliasKey, len(aliases))
	batch := &pgx.Batch{}
	query := currentAliasResolutionSQL()
	for i, alias := range aliases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := alias.Normalize()
		if err != nil {
			return nil, err
		}
		// Account for the complete caller-supplied key before queuing/copying.
		if int64(len(key.Value)) > (maxBytes/int64(len(aliases))-2048)/4 {
			return nil, ErrAlertDependencyBudget
		}
		keys[i] = key
		batch.Queue(query, want.TenantID, want.ContextID, string(key.Kind), key.Value)
	}
	results := reader.SendBatch(ctx, batch)
	defer results.Close()
	out := make([]entity.Resolution, len(aliases))
	for i, key := range keys {
		rows, err := results.Query()
		value, err := scanAliasResolution(rows, err, want, key)
		if err != nil {
			return nil, err
		}
		out[i] = value
	}
	if err := results.Close(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
