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
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type CapacityCircuitMember struct {
	Scope       entity.Scope
	InterfaceID string
}

// CapacityCircuitSnapshot is the complete current effective membership, not
// historical membership, a telemetry grant or an exporter-address association.
// A circuit may span contexts and need not have any flow exporter configured.
type CapacityCircuitSnapshot struct {
	TenantID, TagID, Value string
	Revision               int64
	AsOf                   time.Time
	Members                []CapacityCircuitMember
}

// CapacityCircuitInScope uses the existing effective-tag resolver and current
// source facts in one RLS snapshot. Every candidate context must be authorized
// before its assignments/rules/facts are examined. An unreadable context can
// never silently shorten the circuit, even when no visible member matched yet.
func (s *TagSnapshots) CapacityCircuitInScope(ctx context.Context, sc tenancy.Scope, tagID, value string, maxBytes int64, authorize func(context.Context, entity.ContextRecord) error) (CapacityCircuitSnapshot, error) {
	none := CapacityCircuitSnapshot{}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || sc.Q == nil || authorize == nil {
		return none, tags.ErrScopeMismatch
	}
	if id, err := validRegistryUUID(tagID); err != nil || id != tagID || tags.ValidateValue(value) != nil {
		return none, tags.ErrInvalid
	}
	if maxBytes <= 0 {
		return none, ErrTagSnapshotBudget
	}
	remaining := maxBytes
	charge := func(parts ...string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost := int64(4096)
		for _, part := range parts {
			if int64(len(part)) > (remaining-cost)/32 {
				return ErrTagSnapshotBudget
			}
			cost += int64(len(part)) * 32
		}
		if cost > remaining {
			return ErrTagSnapshotBudget
		}
		remaining -= cost
		return nil
	}
	if err := charge(tagID, value); err != nil {
		return none, err
	}
	var exists bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_tag_definitions WHERE tenant_id=$1 AND id=$2)`, tenant.String(), tagID).Scan(&exists); err != nil {
		return none, err
	}
	if !exists {
		return none, pgx.ErrNoRows
	}
	out := CapacityCircuitSnapshot{TenantID: tenant.String(), TagID: tagID, Value: value, Members: []CapacityCircuitMember{}}
	if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1),transaction_timestamp()`, tenant.String()).Scan(&out.Revision, &out.AsOf); err != nil {
		return none, err
	}
	definitions, err := loadTagDefinitions(ctx, sc, tags.Scope{TenantID: tenant.String()}, charge)
	if err != nil {
		return none, err
	}
	contexts, err := capacityCircuitContextIDs(ctx, sc, charge)
	if err != nil {
		return none, err
	}
	for _, id := range contexts {
		record, err := NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, id)
		if err != nil {
			return none, err
		}
		if err := authorize(ctx, record); err != nil {
			return none, err
		}
		scope := tags.Scope{TenantID: tenant.String(), ContextID: id}
		snapshot, err := loadTagContextSnapshot(ctx, sc, scope, out.Revision, definitions, charge)
		if err != nil {
			return none, err
		}
		members, err := capacityCircuitContextMembers(ctx, sc, scope, snapshot, tagID, value, maxBytes, charge)
		if err != nil {
			return none, err
		}
		out.Members = append(out.Members, members...)
	}
	return out, ctx.Err()
}

func capacityCircuitContextIDs(ctx context.Context, sc tenancy.Scope, charge func(...string) error) ([]string, error) {
	rows, err := sc.Q.Query(ctx, `SELECT c.id::text FROM entity_contexts c WHERE c.tenant_id=$1
        AND EXISTS(SELECT 1 FROM entities n WHERE n.tenant_id=c.tenant_id AND n.context_id=c.id AND n.kind='interface') ORDER BY c.id`, sc.Tenant.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if err := charge(id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func capacityCircuitContextMembers(ctx context.Context, sc tenancy.Scope, scope tags.Scope, snapshot *tags.Snapshot, tagID, value string, maxBytes int64, charge func(...string) error) ([]CapacityCircuitMember, error) {
	ids, err := capacityCircuitInterfaceIDs(ctx, sc, scope.ContextID, charge)
	if err != nil {
		return nil, err
	}
	out := []CapacityCircuitMember{}
	for _, id := range ids {
		subject, err := loadOwnedTagSubject(ctx, sc, scope, TagSubjectReference{Kind: "interface", ID: id}, maxBytes, charge)
		if err != nil {
			return nil, err // ambiguity/unavailable facts must not remove a candidate
		}
		resolved, err := snapshot.ResolveContext(ctx, subject)
		if err != nil {
			return nil, err
		}
		for _, tag := range resolved {
			if tag.TagID == tagID && tag.Value == value {
				if err := charge(id, scope.ContextID, tag.SourceID); err != nil {
					return nil, err
				}
				out = append(out, CapacityCircuitMember{Scope: entity.Scope{TenantID: scope.TenantID, ContextID: scope.ContextID}, InterfaceID: id})
				break // one effective value per immutable tag definition
			}
		}
	}
	return out, nil
}

func capacityCircuitInterfaceIDs(ctx context.Context, sc tenancy.Scope, contextID string, charge func(...string) error) ([]string, error) {
	rows, err := sc.Q.Query(ctx, `SELECT id::text FROM entities WHERE tenant_id=$1 AND context_id=$2 AND kind='interface' ORDER BY id`, sc.Tenant.String(), contextID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if err := charge(id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
