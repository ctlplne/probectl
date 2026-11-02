// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func entityDetailPage(ctx context.Context, s *EntityRegistry, scope entity.Scope,
	id, cursor string, limit int) (entity.Scope, string, string, error) {
	want, err := s.scope(ctx, scope)
	if err != nil {
		return entity.Scope{}, "", "", err
	}
	entityID, err := validRegistryUUID(id)
	if err != nil {
		return entity.Scope{}, "", "", err
	}
	if limit < 1 || limit > 100 {
		return entity.Scope{}, "", "", entity.ErrInvalidPage
	}
	after := uuid.Nil.String()
	if cursor != "" {
		after, err = validRegistryUUID(cursor)
		if err != nil {
			return entity.Scope{}, "", "", entity.ErrInvalidPage
		}
	}
	// An unknown canonical entity is a 404, not an apparently empty page.
	if _, err := s.GetEntity(ctx, want, entityID); err != nil {
		return entity.Scope{}, "", "", err
	}
	return want, entityID, after, nil
}

// ListEntityEvidence pages the durable evidence for one explicit canonical
// entity. Every row remains in its tenant/context compound key; historical
// rows stay visible but Current tracks the live assignment and anchor.
func (s *EntityRegistry) ListEntityEvidence(ctx context.Context, scope entity.Scope,
	id, cursor string, limit int) (entity.EvidencePage, error) {
	want, entityID, after, err := entityDetailPage(ctx, s, scope, id, cursor, limit)
	if err != nil {
		return entity.EvidencePage{}, err
	}
	page := entity.EvidencePage{Scope: want, EntityID: entityID, Items: []entity.EvidenceRecord{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT e.id::text,e.observation_id::text,e.alias_kind,e.alias_value,
			       e.source,e.source_ref,e.agent_id,e.source_kind,e.configured_ref,
			       COALESCE(e.origin_serial,''),COALESCE(e.support_evidence_id::text,''),
			       COALESCE(e.interface_name,''),
			       COALESCE(e.interface_description,''),
			       COALESCE(e.neighbor_protocol,''),COALESCE(e.neighbor_local_if_index,0),
			       COALESCE(e.neighbor_local_port_id,''),COALESCE(e.neighbor_remote_port_id,''),
			       COALESCE(e.neighbor_chassis_id,''),COALESCE(e.neighbor_device_name,''),
			       COALESCE(e.neighbor_management_address,''),
			       e.observed_at,e.expires_at,
			       `+currentEntityEvidenceSQL()+`
			  FROM entity_evidence e
			 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.entity_id=$3
			   AND e.id>$4
			 ORDER BY e.id LIMIT $5`, want.TenantID, want.ContextID, entityID,
			after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item entity.EvidenceRecord
			var aliasKind, sourceKind string
			var neighborIndex int64
			if err := rows.Scan(&item.ID, &item.ObservationID,
				&aliasKind, &item.Alias.Value, &item.Source, &item.SourceRef,
				&item.SourceKey.AgentID, &sourceKind, &item.SourceKey.SourceRef,
				&item.OriginSerial, &item.SupportEvidenceID, &item.InterfaceName,
				&item.InterfaceDescription,
				&item.NeighborProtocol, &neighborIndex,
				&item.NeighborLocalPortID, &item.NeighborRemotePortID,
				&item.NeighborChassisID, &item.NeighborDeviceName,
				&item.NeighborAddress,
				&item.ObservedAt, &item.ExpiresAt, &item.Current); err != nil {
				return err
			}
			if neighborIndex < 0 || neighborIndex > 4294967295 {
				return entity.ErrInvalidClaim
			}
			item.NeighborLocalIfIndex = uint32(neighborIndex)
			item.Alias.Kind = entity.AliasKind(aliasKind)
			item.SourceKey.Kind = entity.SourceKind(sourceKind)
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return entity.EvidencePage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

// ListEntityLinks pages both incoming and outgoing links, retaining the
// evidence source kind so the caller can enforce plane permission on every
// row before exposing an inferred relationship.
func (s *EntityRegistry) ListEntityLinks(ctx context.Context, scope entity.Scope,
	id, cursor string, limit int) (entity.LinkPage, error) {
	want, entityID, after, err := entityDetailPage(ctx, s, scope, id, cursor, limit)
	if err != nil {
		return entity.LinkPage{}, err
	}
	page := entity.LinkPage{Scope: want, EntityID: entityID, Items: []entity.LinkRecord{}}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT l.id::text,l.from_entity_id::text,l.to_entity_id::text,
			       l.evidence_id::text,l.kind,e.source_kind,l.observed_at
			  FROM entity_links l
			  JOIN entity_evidence e ON
			       (e.tenant_id,e.context_id,e.id)=
			       (l.tenant_id,l.context_id,l.evidence_id)
			 WHERE l.tenant_id=$1 AND l.context_id=$2
			   AND (l.from_entity_id=$3 OR l.to_entity_id=$3)
			   AND l.id>$4
			 ORDER BY l.id LIMIT $5`, want.TenantID, want.ContextID, entityID,
			after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item entity.LinkRecord
			if err := rows.Scan(&item.ID, &item.FromEntityID, &item.ToEntityID,
				&item.EvidenceID, &item.Kind, &item.SourceKind,
				&item.ObservedAt); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return entity.LinkPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}
