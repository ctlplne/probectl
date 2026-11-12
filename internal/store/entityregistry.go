// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrEntityRegistryUnavailable = errors.New("entity registry is unavailable")

// EntityRegistry reads durable evidence through the tenant's real Postgres
// isolation target. Callers must already carry the authenticated tenant in ctx;
// a tenant ID in an alias or packet never selects a tenant transaction.
type EntityRegistry struct{ pool *pgxpool.Pool }

func NewEntityRegistry(pool *pgxpool.Pool) *EntityRegistry {
	return &EntityRegistry{pool: pool}
}

// ListEntityContexts lets an operator choose an existing routing context
// without guessing a UUID. FORCE RLS keeps the page inside the caller tenant.
func (s *EntityRegistry) ListEntityContexts(ctx context.Context, cursor string, limit int) (entity.ContextPage, error) {
	if s == nil || s.pool == nil {
		return entity.ContextPage{}, ErrEntityRegistryUnavailable
	}
	if limit < 1 || limit > 100 {
		return entity.ContextPage{}, entity.ErrInvalidPage
	}
	after := uuid.Nil
	var err error
	if cursor != "" {
		after, err = uuid.Parse(cursor)
		if err != nil || after == uuid.Nil {
			return entity.ContextPage{}, entity.ErrInvalidPage
		}
	}
	page := entity.ContextPage{Items: []entity.ContextRecord{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT id::text,site_id::text,vrf_id::text,
			site_label,vrf_label,created_at
			FROM entity_contexts WHERE tenant_id=$1 AND id>$2
			ORDER BY id LIMIT $3`, sc.Tenant.String(), after.String(), limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item := entity.ContextRecord{TenantID: sc.Tenant.String()}
			if err := rows.Scan(&item.ContextID, &item.SiteID, &item.VRFID,
				&item.SiteLabel, &item.VRFLabel, &item.CreatedAt); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return entity.ContextPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ContextID
	}
	return page, nil
}

// GetEntityContext loads the policy attributes for one tenant/context through
// the same forced-RLS transaction used by registry reads. A caller cannot
// substitute labels or IDs from a request when authorizing entity operations.
func (s *EntityRegistry) GetEntityContext(ctx context.Context, scope entity.Scope) (entity.ContextRecord, error) {
	want, err := s.scope(ctx, scope)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	var record entity.ContextRecord
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = s.GetEntityContextInScope(ctx, sc, want.ContextID)
		return err
	})
	if err != nil {
		return entity.ContextRecord{}, err
	}
	return record, nil
}

// GetEntityContextInScope reads current stored policy attributes using an
// existing tenant transaction. It never acquires a connection or supplies
// lifecycle, credential, writer-fence or publication authority.
func (s *EntityRegistry) GetEntityContextInScope(ctx context.Context, sc tenancy.Scope, contextID string) (entity.ContextRecord, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return entity.ContextRecord{}, entity.ErrScopeMismatch
	}
	if sc.Q == nil {
		return entity.ContextRecord{}, ErrEntityRegistryUnavailable
	}
	want, err := (entity.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}).Normalize()
	if err != nil {
		return entity.ContextRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		return entity.ContextRecord{}, err
	}
	record := entity.ContextRecord{TenantID: want.TenantID, ContextID: want.ContextID}
	err = sc.Q.QueryRow(ctx, `SELECT site_id::text,vrf_id::text,site_label,vrf_label,created_at
		FROM entity_contexts WHERE tenant_id=$1 AND id=$2`,
		want.TenantID, want.ContextID).Scan(&record.SiteID, &record.VRFID,
		&record.SiteLabel, &record.VRFLabel, &record.CreatedAt)
	if err != nil {
		return entity.ContextRecord{}, err
	}
	return record, nil
}

// ResolveSourceContext returns the routing context assigned by the operator
// to an authenticated producer and configured source. The caller must obtain
// AgentID from transport or registration, not the telemetry payload. Missing
// or expired assignments return no row; there is no default/global context.
func (s *EntityRegistry) ResolveSourceContext(ctx context.Context, tenantID string, source entity.SourceKey) (entity.Scope, error) {
	if s == nil || s.pool == nil {
		return entity.Scope{}, ErrEntityRegistryUnavailable
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil {
		return entity.Scope{}, entity.ErrInvalidScope
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant.String() {
		return entity.Scope{}, entity.ErrScopeMismatch
	}
	key, err := source.Normalize()
	if err != nil {
		return entity.Scope{}, err
	}
	var contextID string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `
			SELECT m.context_id::text
			  FROM entity_source_contexts m
			  JOIN entity_agent_contexts a ON
			       (a.tenant_id,a.agent_id,a.context_id)=
			       (m.tenant_id,m.agent_id,m.context_id)
			 WHERE m.tenant_id=$1 AND m.agent_id=$2
			   AND m.source_kind=$3 AND m.source_ref=$4
			   AND m.assigned_at <= statement_timestamp()
			   AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
			   AND a.assigned_at <= statement_timestamp()
			   AND (a.expires_at IS NULL OR a.expires_at > statement_timestamp())
			   AND NOT EXISTS (
			       SELECT 1 FROM agent_identities i
			        WHERE i.tenant_id=$1 AND i.agent_id=$2
			          AND i.revoked_at IS NOT NULL
			          AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')`,
			tenant.String(), key.AgentID, string(key.Kind), key.SourceRef).Scan(&contextID)
	})
	if err != nil {
		return entity.Scope{}, err
	}
	return (entity.Scope{TenantID: tenant.String(), ContextID: contextID}).Normalize()
}

func (s *EntityRegistry) scope(ctx context.Context, raw entity.Scope) (entity.Scope, error) {
	if s == nil || s.pool == nil {
		return entity.Scope{}, ErrEntityRegistryUnavailable
	}
	want, err := raw.Normalize()
	if err != nil {
		return entity.Scope{}, err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != want.TenantID {
		return entity.Scope{}, entity.ErrScopeMismatch
	}
	return want, nil
}

// GetEntity requires both the authenticated tenant and an explicit routing
// context. A foreign UUID returns no row under the forced-RLS transaction.
func (s *EntityRegistry) GetEntity(ctx context.Context, scope entity.Scope, id string) (entity.Record, error) {
	want, err := s.scope(ctx, scope)
	if err != nil {
		return entity.Record{}, err
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return entity.Record{}, entity.ErrInvalidClaim
	}
	var record entity.Record
	var kind string
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `
			SELECT id::text, kind, label, created_at, updated_at,COALESCE(network_prefix::text,'')
			  FROM entities
			 WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			want.TenantID, want.ContextID, parsed.String()).Scan(
			&record.ID, &kind, &record.Label, &record.CreatedAt, &record.UpdatedAt, &record.NetworkPrefix)
	})
	if err != nil {
		return entity.Record{}, err
	}
	record.Scope, record.Kind = want, entity.Kind(kind)
	if err := entity.ValidateKind(record.Kind); err != nil {
		return entity.Record{}, err
	}
	return record, nil
}

// ListEntities returns one bounded keyset page. The UUID cursor is meaningful
// only inside the authenticated tenant and explicit routing context used by
// this call; it can never select another context's rows.
func (s *EntityRegistry) ListEntities(ctx context.Context, scope entity.Scope, cursor string, limit int) (entity.Page, error) {
	want, err := s.scope(ctx, scope)
	if err != nil {
		return entity.Page{}, err
	}
	if limit < 1 || limit > 100 {
		return entity.Page{}, entity.ErrInvalidPage
	}
	after := uuid.Nil
	if cursor != "" {
		after, err = uuid.Parse(cursor)
		if err != nil || after == uuid.Nil {
			return entity.Page{}, entity.ErrInvalidPage
		}
	}
	page := entity.Page{Scope: want, Items: []entity.Record{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT id::text,kind,label,created_at,updated_at,COALESCE(network_prefix::text,'')
			  FROM entities
			 WHERE tenant_id=$1 AND context_id=$2 AND id > $3
			 ORDER BY id LIMIT $4`, want.TenantID, want.ContextID,
			after.String(), limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record entity.Record
			var kind string
			record.Scope = want
			if err := rows.Scan(&record.ID, &kind, &record.Label,
				&record.CreatedAt, &record.UpdatedAt, &record.NetworkPrefix); err != nil {
				return err
			}
			record.Kind = entity.Kind(kind)
			if err := entity.ValidateKind(record.Kind); err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		return rows.Err()
	})
	if err != nil {
		return entity.Page{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

// ResolveAlias returns at most three representative candidates. Evidence from
// a revoked or re-bound source remains stored but is not current evidence.
// DISTINCT ON selects one current row per canonical entity. A fourth row marks
// truncation but cannot change a resolved answer into a conflict: if two
// distinct entities exist, the first two rows already show both.
func (s *EntityRegistry) ResolveAlias(ctx context.Context, scope entity.Scope, alias entity.AliasKey) (entity.Resolution, error) {
	want, err := s.scope(ctx, scope)
	if err != nil {
		return entity.Resolution{}, err
	}
	key, err := alias.Normalize()
	if err != nil {
		return entity.Resolution{}, err
	}
	var result entity.Resolution
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var lookupErr error
		result, lookupErr = ResolveAliasInScope(ctx, sc, want, key)
		return lookupErr
	})
	return result, err
}

// ResolveAliasInScope uses the caller's existing tenant transaction. Incident
// correlation calls it while holding the per-tenant advisory lock, so source
// assignment and current evidence cannot be read in a second transaction.
func ResolveAliasInScope(ctx context.Context, sc tenancy.Scope,
	scope entity.Scope, alias entity.AliasKey) (entity.Resolution, error) {
	want, err := scope.Normalize()
	if err != nil || want.TenantID != sc.Tenant.String() {
		return entity.Resolution{}, entity.ErrScopeMismatch
	}
	key, err := alias.Normalize()
	if err != nil {
		return entity.Resolution{}, err
	}
	rows, err := sc.Q.Query(ctx, currentAliasResolutionSQL(), want.TenantID, want.ContextID, string(key.Kind), key.Value)
	return scanAliasResolution(rows, err, want, key)
}

// Population lookup uses this exact query too: ambiguity and independent
// current support must not depend on the number of aliases in an operation.
func currentAliasResolutionSQL() string {
	return `
			SELECT DISTINCT ON (resolved_node.id)
			       e.id::text, resolved_node.id::text, resolved_node.kind, e.source, e.source_ref,
		       e.agent_id, e.source_kind, e.configured_ref, e.observed_at,
		       COALESCE(e.support_evidence_id::text,'')
			  FROM entity_evidence e
			  JOIN entities n ON (n.tenant_id, n.context_id, n.id) =
			                     (e.tenant_id, e.context_id, e.entity_id)
		  JOIN entities resolved_node ON (resolved_node.tenant_id,resolved_node.context_id,resolved_node.id)=
		       (e.tenant_id,e.context_id,
		        COALESCE(CASE WHEN e.alias_kind='address' THEN n.parent_entity_id END,
		                 e.entity_id))
		  JOIN entity_source_contexts m ON
			       (m.tenant_id, m.context_id, m.agent_id, m.source_kind, m.source_ref) =
			       (e.tenant_id, e.context_id, e.agent_id, e.source_kind, e.configured_ref)
		     AND ((e.support_evidence_id IS NULL AND
		           m.anchor_entity_id = COALESCE(n.parent_entity_id,e.entity_id))
		          OR (m.anchor_entity_id IS NULL AND ` + currentInferredSupportSQL("e") + `))
		  JOIN entity_agent_contexts a ON
		       (a.tenant_id, a.agent_id, a.context_id) =
		       (m.tenant_id, m.agent_id, m.context_id)
			 WHERE e.tenant_id = $1 AND e.context_id = $2
			   AND e.alias_kind = $3 AND e.alias_value = $4
			   AND ` + currentPhysicalNeighborSQL + `
			   AND e.observed_at <= statement_timestamp()
			   AND (e.expires_at IS NULL OR e.expires_at > statement_timestamp())
			   AND m.assigned_at <= statement_timestamp()
			   AND m.assigned_at <= e.observed_at
			   AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
		   AND a.assigned_at <= statement_timestamp()
		   AND a.assigned_at <= e.observed_at
		   AND (a.expires_at IS NULL OR a.expires_at > statement_timestamp())
			   AND NOT EXISTS (
			       SELECT 1 FROM agent_identities i
			        WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
			          AND i.revoked_at IS NOT NULL
			          AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
			   AND EXISTS (
			       SELECT 1 FROM agent_identities sender
			        WHERE sender.tenant_id=e.tenant_id
			          AND sender.agent_id=e.agent_id
			          AND sender.serial=e.sender_serial
			          AND sender.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/entity/' || e.agent_id
			          AND sender.revoked_at IS NULL
			          AND sender.issued_at <= e.observed_at
			          AND sender.not_after > statement_timestamp())
			   AND (e.source_kind <> 'bmp_peer' OR EXISTS (
			       SELECT 1 FROM agent_identities origin
			        WHERE origin.tenant_id=e.tenant_id
			          AND origin.agent_id=e.configured_ref
			          AND origin.serial=e.origin_serial
			          AND origin.spiffe_id='spiffe://probectl/tenant/' || e.tenant_id::text || '/bmp/' || e.configured_ref
			          AND origin.revoked_at IS NULL
			          AND origin.issued_at <= e.observed_at
			          AND origin.not_after > statement_timestamp()))
			 ORDER BY resolved_node.id, e.observed_at DESC, e.id
			 LIMIT 4`
}

func scanAliasResolution(rows pgx.Rows, err error, want entity.Scope, key entity.AliasKey) (entity.Resolution, error) {
	if err != nil {
		return entity.Resolution{}, err
	}
	var claims []entity.Claim
	defer rows.Close()
	for rows.Next() {
		var claim entity.Claim
		var kind, sourceKind string
		claim.Scope, claim.Alias = want, key
		if err := rows.Scan(&claim.EvidenceID, &claim.EntityID,
			&kind, &claim.Source, &claim.SourceRef, &claim.SourceKey.AgentID,
			&sourceKind, &claim.SourceKey.SourceRef, &claim.ObservedAt,
			&claim.SupportEvidenceID); err != nil {
			return entity.Resolution{}, err
		}
		claim.EntityKind = entity.Kind(kind)
		claim.SourceKey.Kind = entity.SourceKind(sourceKind)
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return entity.Resolution{}, err
	}
	more := len(claims) > 3
	if more {
		claims = claims[:3]
	}
	result, err := entity.Resolve(want, key, claims)
	if err != nil {
		return entity.Resolution{}, err
	}
	result.MoreCandidates = more
	return result, nil
}
