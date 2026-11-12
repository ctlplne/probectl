// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrIncidentImpactBudget = errors.New("complete incident impact inputs exceed admitted memory")

// IncidentImpactEntity is a persisted canonical reference with its complete
// signal citations. It does not grant access to the entity or its data sources.
type IncidentImpactEntity struct {
	ContextID, EntityID string
	IncidentRoot        bool
	SignalIDs           []string
}

// IncidentImpactInputs comes from one caller-owned tenant snapshot. Unknown
// identities remain explicit; free-form signal attributes never supply them.
type IncidentImpactInputs struct {
	TenantID, IncidentID  string
	StartedAt, LastSeenAt time.Time
	ResolvedAt            *time.Time
	RootUnresolved        bool
	SourceGeneration      int64
	Entities              []IncidentImpactEntity
	UnresolvedSignalIDs   []string
}

// ImpactInputs reads the entire incident membership independently of the room's
// display pagination. The caller authorizes incident access first, then every
// returned canonical reference before reading source metadata. All transfer is
// fixed-size UUID/time data under FORCE-RLS and an explicit tenant predicate;
// a resource or scan failure returns no usable prefix.
func (Incidents) ImpactInputs(ctx context.Context, sc tenancy.Scope, id string, maxBytes int64) (*IncidentImpactInputs, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if _, err := validRegistryUUID(id); err != nil {
		return nil, err
	}
	if maxBytes < 512 {
		return nil, ErrIncidentImpactBudget
	}
	var rootContext, rootEntity *string
	var verified bool
	out := &IncidentImpactInputs{TenantID: bound.String(), IncidentID: id,
		Entities: []IncidentImpactEntity{}, UnresolvedSignalIDs: []string{}}
	if err := sc.Q.QueryRow(ctx, `SELECT started_at,last_seen_at,resolved_at,
		entity_context_id::text,entity_id::text,identity_lookup_attempted
		FROM incidents WHERE tenant_id=$1 AND id=$2`, bound.String(), id).
		Scan(&out.StartedAt, &out.LastSeenAt, &out.ResolvedAt, &rootContext, &rootEntity, &verified); err != nil {
		return nil, notFound("incident", err)
	}
	remaining := maxBytes - 512
	var invalidating bool
	if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(epoch.generation,1),COALESCE(epoch.invalidating OR epoch.observation_erasing,false)
		FROM (VALUES($1::uuid)) tenant(id) LEFT JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=tenant.id`, bound.String()).
		Scan(&out.SourceGeneration, &invalidating); err != nil {
		return nil, err
	}
	if invalidating || out.SourceGeneration <= 0 {
		return nil, sourceepoch.ErrInvalidating
	}
	indices := map[string]int{}
	add := func(contextID, entityID, signalID string, root bool) error {
		key := contextID + ":" + entityID
		index, exists := indices[key]
		charge := int64(128)
		if !exists {
			charge += 256
		}
		if charge > remaining {
			return ErrIncidentImpactBudget
		}
		remaining -= charge
		if !exists {
			index = len(out.Entities)
			indices[key] = index
			out.Entities = append(out.Entities, IncidentImpactEntity{ContextID: contextID, EntityID: entityID, SignalIDs: []string{}})
		}
		out.Entities[index].IncidentRoot = out.Entities[index].IncidentRoot || root
		if signalID != "" {
			out.Entities[index].SignalIDs = append(out.Entities[index].SignalIDs, signalID)
		}
		return nil
	}
	out.RootUnresolved = !verified || rootContext == nil || rootEntity == nil
	if !out.RootUnresolved {
		if err := add(*rootContext, *rootEntity, "", true); err != nil {
			return nil, err
		}
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,entity_context_id::text,entity_id::text,identity_lookup_attempted
		FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 ORDER BY id`, bound.String(), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var signal string
		var routingContext, canonicalEntity *string
		if err := rows.Scan(&signal, &routingContext, &canonicalEntity, &verified); err != nil {
			return nil, err
		}
		if verified && routingContext != nil && canonicalEntity != nil {
			if err := add(*routingContext, *canonicalEntity, signal, false); err != nil {
				return nil, err
			}
		} else {
			if remaining < 128 {
				return nil, ErrIncidentImpactBudget
			}
			remaining -= 128
			out.UnresolvedSignalIDs = append(out.UnresolvedSignalIDs, signal)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out.Entities, func(i, j int) bool {
		a, b := out.Entities[i], out.Entities[j]
		if a.ContextID != b.ContextID {
			return a.ContextID < b.ContextID
		}
		return a.EntityID < b.EntityID
	})
	return out, nil
}
