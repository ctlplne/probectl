// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrTagSnapshotUnavailable = errors.New("tag snapshot store is unavailable")
	ErrTagSnapshotBudget      = errors.New("tag snapshot exceeds query memory budget")
)

// TagSnapshots loads only the authenticated tenant's current definitions and
// one routing context's assignments/rules. Postgres FORCE RLS is the outer
// boundary; explicit predicates make the intended scope visible in every SQL
// statement. The returned immutable object is safe to reuse across pages.
type TagSnapshots struct{ pool *pgxpool.Pool }

func NewTagSnapshots(pool *pgxpool.Pool) *TagSnapshots {
	return &TagSnapshots{pool: pool}
}

// Load materializes one revision under a read-only REPEATABLE READ tenant
// transaction. maxBytes is the caller's existing Explorer memory allowance;
// even a schema-valid 25,000-rule set must be refused rather than truncated
// if its resolved vocabulary would exceed that query's budget.
func (s *TagSnapshots) Load(ctx context.Context, scope tags.Scope, maxBytes int64) (*tags.Snapshot, error) {
	if s == nil || s.pool == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	if _, err := tags.NewSnapshot(scope, 1, nil, nil, nil); err != nil {
		return nil, err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != scope.TenantID {
		return nil, tags.ErrScopeMismatch
	}
	var snapshot *tags.Snapshot
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var ownsContext bool
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entity_contexts
			WHERE tenant_id=$1 AND id=$2)`, scope.TenantID, scope.ContextID).
			Scan(&ownsContext); err != nil {
			return err
		}
		if !ownsContext {
			return tags.ErrScopeMismatch
		}
		var revision int64
		err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
			WHERE tenant_id=$1`, scope.TenantID).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			revision = 1
		} else if err != nil {
			return err
		}
		used := int64(0)
		charge := func(parts ...string) error {
			// Conservatively include map/slice, compiled regex/index nodes and
			// string headers; the caller reserves this from its Explorer budget.
			used += 2048
			for _, part := range parts {
				used += int64(len(part))
			}
			if used > maxBytes {
				return ErrTagSnapshotBudget
			}
			return nil
		}
		definitions, err := loadTagDefinitions(ctx, sc, scope, charge)
		if err != nil {
			return err
		}
		assignments, err := loadTagAssignments(ctx, sc, scope, charge)
		if err != nil {
			return err
		}
		rules, err := loadTagRules(ctx, sc, scope, charge)
		if err != nil {
			return err
		}
		snapshot, err = tags.NewSnapshot(scope, revision, definitions, assignments, rules)
		return err
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func loadTagDefinitions(ctx context.Context, sc tenancy.Scope, scope tags.Scope,
	charge func(...string) error) ([]tags.Definition, error) {
	rows, err := sc.Q.Query(ctx, `SELECT id::text,key FROM tenant_tag_definitions
		WHERE tenant_id=$1 ORDER BY id LIMIT $2`, scope.TenantID, tags.MaxDefinitions+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tags.Definition
	for rows.Next() {
		item := tags.Definition{TenantID: scope.TenantID}
		if err := rows.Scan(&item.ID, &item.Key); err != nil {
			return nil, err
		}
		if err := charge(item.ID, item.Key); err != nil {
			return nil, err
		}
		out = append(out, item)
		if len(out) > tags.MaxDefinitions {
			return nil, tags.ErrInvalid
		}
	}
	return out, rows.Err()
}

func loadTagAssignments(ctx context.Context, sc tenancy.Scope, scope tags.Scope,
	charge func(...string) error) ([]tags.Assignment, error) {
	rows, err := sc.Q.Query(ctx, `SELECT tag_id::text,target_kind,
		COALESCE(entity_id::text,''),COALESCE(agent_id,''),COALESCE(test_id::text,''),
		COALESCE(exporter_agent_id,''),COALESCE(exporter_source_ref,''),
		value,source,COALESCE(source_ref,'')
		FROM tenant_tag_assignments
		WHERE tenant_id=$1 AND context_id=$2
		ORDER BY id LIMIT $3`, scope.TenantID, scope.ContextID, tags.MaxAssignments+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tags.Assignment
	for rows.Next() {
		item := tags.Assignment{Scope: scope}
		var entityID, agentID, testID, exporterAgent, exporterRef string
		if err := rows.Scan(&item.TagID, &item.TargetKind, &entityID, &agentID,
			&testID, &exporterAgent, &exporterRef, &item.Value,
			&item.Source, &item.SourceRef); err != nil {
			return nil, err
		}
		switch item.TargetKind {
		case "device", "interface", "prefix":
			item.TargetID = entityID
		case "agent":
			item.TargetID = agentID
		case "test":
			item.TargetID = testID
		case "exporter":
			item.TargetID, err = tags.ExporterTargetID(exporterAgent, exporterRef)
			if err != nil {
				return nil, err
			}
		default:
			return nil, tags.ErrInvalid
		}
		if err := charge(item.TagID, item.TargetKind, item.TargetID,
			item.Value, item.Source, item.SourceRef); err != nil {
			return nil, err
		}
		out = append(out, item)
		if len(out) > tags.MaxAssignments {
			return nil, tags.ErrInvalid
		}
	}
	return out, rows.Err()
}

func loadTagRules(ctx context.Context, sc tenancy.Scope, scope tags.Scope,
	charge func(...string) error) ([]tags.Rule, error) {
	rows, err := sc.Q.Query(ctx, `SELECT id::text,tag_id::text,target_kind,match_kind,
		COALESCE(address_side,''),COALESCE(cidr::text,''),
		COALESCE(name_pattern,''),COALESCE(snmp_field,''),COALESCE(snmp_value,''),
		value,priority FROM tenant_tag_rules
		WHERE tenant_id=$1 AND context_id=$2
		ORDER BY id LIMIT $3`, scope.TenantID, scope.ContextID, tags.MaxRules+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tags.Rule
	for rows.Next() {
		item := tags.Rule{Scope: scope}
		if err := rows.Scan(&item.ID, &item.TagID, &item.TargetKind, &item.Match,
			&item.AddressSide, &item.CIDR, &item.NamePattern,
			&item.SNMPField, &item.SNMPValue, &item.Value, &item.Priority); err != nil {
			return nil, err
		}
		if err := charge(item.ID, item.TagID, item.TargetKind, item.Match,
			item.AddressSide, item.CIDR, item.NamePattern, item.SNMPField,
			item.SNMPValue, item.Value); err != nil {
			return nil, err
		}
		out = append(out, item)
		if len(out) > tags.MaxRules {
			return nil, tags.ErrInvalid
		}
	}
	return out, rows.Err()
}
