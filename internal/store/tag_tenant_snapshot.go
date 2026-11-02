// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TenantTagSnapshot is one revision of operator-owned flow exporter bindings
// and their context-local tags. Raw flow rows cannot choose a context using
// their claimed agent ID: the bus verifies the tenant lane, not the sender.
// An exporter address is eligible only when exactly one active owned binding
// names it in the tenant. All maps and compiled tag snapshots are immutable.
type TenantTagSnapshot struct {
	tenantID    string
	revision    int64
	definitions []tags.Definition
	byAddress   map[string]tagExporterBinding
	byContext   map[string]*tags.Snapshot
}

// TagExporterProjection is a bounded, tenant-local lookup row for query
// execution. It carries no agent claim, source reference or provenance ID.
type TagExporterProjection struct {
	Exporter string
	Values   map[string]string
}

type tagExporterBinding struct {
	contextID string
	agentID   string
	sourceRef string
}

func (s *TenantTagSnapshot) Revision() (int64, error) {
	if s == nil || s.tenantID == "" || s.revision <= 0 {
		return 0, ErrTagSnapshotUnavailable
	}
	return s.revision, nil
}

// Definitions returns independent copies of the keys captured at this
// revision. A caller may build its tenant-specific query vocabulary from
// these; it must never use a process-global registry for dynamic keys.
func (s *TenantTagSnapshot) Definitions() ([]tags.Definition, error) {
	if _, err := s.Revision(); err != nil {
		return nil, err
	}
	return append([]tags.Definition(nil), s.definitions...), nil
}

// ProjectExporters resolves each uniquely owned address once, before a query.
// The caller's byte budget bounds the whole lookup; partial projections are
// never returned because they would silently label some flow rows unmatched.
func (s *TenantTagSnapshot) ProjectExporters(maxBytes int64) ([]TagExporterProjection, error) {
	if _, err := s.Revision(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	// Sorting and retaining candidate addresses has a cost even when none
	// resolves to a tag. Refuse before allocating from a smaller query budget.
	if int64(len(s.byAddress)) > maxBytes/128 {
		return nil, ErrTagSnapshotBudget
	}
	addresses := make([]string, 0, len(s.byAddress))
	for address := range s.byAddress {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	used := int64(0)
	out := []TagExporterProjection{}
	for _, address := range addresses {
		resolved, err := s.ResolveExporter(netip.MustParseAddr(address))
		if err != nil {
			return nil, err
		}
		if len(resolved) == 0 {
			continue
		}
		row := TagExporterProjection{Exporter: address, Values: make(map[string]string, len(resolved))}
		used += 256 + int64(len(address))
		for _, tag := range resolved {
			used += 128 + int64(len(tag.Key)+len(tag.Value))
			if used > maxBytes {
				return nil, ErrTagSnapshotBudget
			}
			row.Values[tag.Key] = tag.Value
		}
		out = append(out, row)
	}
	return out, nil
}

// ResolveExporter uses only the observed exporter address to select a binding.
// A claimed agent ID from a raw row is deliberately absent from this API.
// Unknown, expired and multiply-owned addresses yield no tags.
func (s *TenantTagSnapshot) ResolveExporter(exporter netip.Addr) ([]tags.Resolved, error) {
	if _, err := s.Revision(); err != nil {
		return nil, err
	}
	if !exporter.IsValid() || exporter.Zone() != "" {
		return nil, nil
	}
	exporter = exporter.Unmap()
	binding, ok := s.byAddress[exporter.String()]
	if !ok {
		return nil, nil
	}
	contextSnapshot := s.byContext[binding.contextID]
	if contextSnapshot == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	id, err := tags.ExporterTargetID(binding.agentID, binding.sourceRef)
	if err != nil {
		return nil, err
	}
	return contextSnapshot.Resolve(tags.Subject{
		Scope: tags.Scope{TenantID: s.tenantID, ContextID: binding.contextID},
		Kind:  "exporter", ID: id, AddressSide: "exporter", Address: exporter,
	})
}

// LoadTenant charges one caller budget and captures bindings, definitions,
// assignments, rules and revision inside one tenant read snapshot. It never
// performs a context lookup from a raw row or lets an ambiguous address win.
func (s *TagSnapshots) LoadTenant(ctx context.Context, maxBytes int64) (*TenantTagSnapshot, error) {
	if s == nil || s.pool == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, tags.ErrScopeMismatch
	}
	tenantID := tenant.String()
	var result *TenantTagSnapshot
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var revision int64
		err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
			WHERE tenant_id=$1`, tenantID).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			revision = 1
		} else if err != nil {
			return err
		}
		used := int64(0)
		charge := func(parts ...string) error {
			amount := int64(2048)
			for _, part := range parts {
				amount += int64(len(part))
			}
			if amount > maxBytes-used {
				return ErrTagSnapshotBudget
			}
			used += amount
			return nil
		}
		bindings, err := loadTagExporterBindings(ctx, sc, tenantID, maxBytes, charge)
		if err != nil {
			return err
		}
		definitions, err := loadTagDefinitions(ctx, sc,
			tags.Scope{TenantID: tenantID}, charge)
		if err != nil {
			return err
		}
		contexts := make(map[string]bool)
		for _, binding := range bindings {
			contexts[binding.contextID] = true
		}
		contextIDs := make([]string, 0, len(contexts))
		for contextID := range contexts {
			contextIDs = append(contextIDs, contextID)
		}
		sort.Strings(contextIDs)
		contextSnapshots := make(map[string]*tags.Snapshot, len(contexts))
		for _, contextID := range contextIDs {
			// NewSnapshot copies every definition per context. Charge that
			// copy as well as the assignment/rule rows it compiles.
			if err := charge(contextID); err != nil {
				return err
			}
			for _, def := range definitions {
				if err := charge(def.ID, def.Key); err != nil {
					return err
				}
			}
			scope := tags.Scope{TenantID: tenantID, ContextID: contextID}
			assignments, err := loadTagAssignments(ctx, sc, scope, charge)
			if err != nil {
				return err
			}
			rules, err := loadTagRules(ctx, sc, scope, charge)
			if err != nil {
				return err
			}
			contextSnapshots[contextID], err = tags.NewSnapshot(scope, revision,
				definitions, assignments, rules)
			if err != nil {
				return err
			}
		}
		result = &TenantTagSnapshot{tenantID: tenantID, revision: revision,
			definitions: append([]tags.Definition(nil), definitions...),
			byAddress:   bindings, byContext: contextSnapshots}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func loadTagExporterBindings(ctx context.Context, sc tenancy.Scope, tenantID string,
	maxBytes int64, charge func(...string) error) (map[string]tagExporterBinding, error) {
	// One row consumes at least 2 KiB. Fetch one extra row to refuse a
	// truncated source catalogue rather than silently omit a competing owner.
	limit := maxBytes/2048 + 1
	rows, err := sc.Q.Query(ctx, `SELECT s.agent_id,s.source_ref,s.context_id::text
		FROM entity_source_contexts s
		JOIN entity_agent_contexts a
		  ON a.tenant_id=s.tenant_id AND a.agent_id=s.agent_id
		 AND a.context_id=s.context_id
		WHERE s.tenant_id=$1 AND a.tenant_id=$1
		  AND s.source_kind='flow_exporter'
		  AND s.assigned_at<=now() AND (s.expires_at IS NULL OR s.expires_at>now())
		  AND a.assigned_at<=now() AND (a.expires_at IS NULL OR a.expires_at>now())
		ORDER BY s.agent_id,s.source_ref LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]tagExporterBinding)
	ambiguous := make(map[string]bool)
	seen := int64(0)
	for rows.Next() {
		seen++
		if seen >= limit {
			rows.Close()
			return nil, ErrTagSnapshotBudget
		}
		var binding tagExporterBinding
		if err := rows.Scan(&binding.agentID, &binding.sourceRef, &binding.contextID); err != nil {
			rows.Close()
			return nil, err
		}
		if err := charge(binding.agentID, binding.sourceRef, binding.contextID); err != nil {
			rows.Close()
			return nil, err
		}
		addr, err := netip.ParseAddr(binding.sourceRef)
		if err != nil || addr.Zone() != "" {
			continue // an opaque source key cannot match a flow exporter IP
		}
		key := addr.Unmap().String()
		if _, exists := bindings[key]; exists || ambiguous[key] {
			delete(bindings, key)
			ambiguous[key] = true
			continue
		}
		bindings[key] = binding
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return bindings, nil
}
