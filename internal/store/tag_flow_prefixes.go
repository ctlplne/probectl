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

func loadFlowTagPrefixes(ctx context.Context, sc tenancy.Scope, snapshot *TenantTagSnapshot, maxBytes int64, charge func(...string) error) (map[string][]tags.PrefixProjection, error) {
	contexts := map[string]bool{}
	for _, binding := range snapshot.byAddress {
		contexts[binding.contextID] = true
	}
	ids := make([]string, 0, len(contexts))
	for id := range contexts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := map[string][]tags.PrefixProjection{}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		values, err := loadFlowTagContextPrefixes(ctx, sc, snapshot, id, maxBytes, charge)
		if err != nil {
			return nil, err
		}
		result[id] = values
	}
	return result, nil
}

// Only explicit current typed networks can associate a row address. Labels
// and BGP attributes never supply ranges or routing-context authority.
func loadFlowTagContextPrefixes(ctx context.Context, sc tenancy.Scope, snapshot *TenantTagSnapshot, contextID string, maxBytes int64, charge func(...string) error) ([]tags.PrefixProjection, error) {
	limit := maxBytes/2048 + 1
	rows, err := sc.Q.Query(ctx, `SELECT id::text,network_prefix::text FROM entities
        WHERE tenant_id=$1 AND context_id=$2 AND kind='prefix' AND network_prefix IS NOT NULL
        ORDER BY network_prefix,id LIMIT $3`, sc.Tenant.String(), contextID, limit)
	if err != nil {
		return nil, err
	}
	var candidates []tags.PrefixProjection
	for rows.Next() {
		if int64(len(candidates))+1 >= limit {
			rows.Close()
			return nil, ErrTagSnapshotBudget
		}
		var id, network string
		if err := rows.Scan(&id, &network); err != nil {
			rows.Close()
			return nil, err
		}
		if err := charge(id, network); err != nil {
			rows.Close()
			return nil, err
		}
		prefix, err := netip.ParsePrefix(network)
		if err != nil || prefix != prefix.Masked() {
			rows.Close()
			return nil, ErrTagSnapshotUnavailable
		}
		candidates = append(candidates, tags.PrefixProjection{Scope: tags.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}, ID: id, Network: prefix})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	compiled := snapshot.byContext[contextID]
	if compiled == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := &candidates[i]
		subject, err := loadOwnedTagSubject(ctx, sc, item.Scope, TagSubjectReference{Kind: "prefix", ID: item.ID}, maxBytes, charge)
		switch {
		case errors.Is(err, pgx.ErrNoRows), errors.Is(err, ErrTagSubjectFactsAmbiguous):
			continue // Preserve the known range as an empty winner; no ancestor fallback.
		case err != nil:
			return nil, err
		}
		resolved, err := compiled.ResolveContext(ctx, subject)
		if err != nil {
			return nil, err
		}
		item.Values = map[string]string{}
		for _, tag := range resolved {
			if err := charge(tag.Key, tag.Value); err != nil {
				return nil, err
			}
			item.Values[tag.Key] = tag.Value
		}
	}
	return candidates, nil
}

// ProjectAuthorizedPrefixesContext makes independent private backend copies.
// A prefix context without a unique owned exporter cannot enter the lookup.
func (s *TenantTagSnapshot) ProjectAuthorizedPrefixesContext(ctx context.Context, allowed, sourceAllowed map[string]bool, maxBytes int64) ([]tags.PrefixProjection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := s.Revision(); err != nil {
		return nil, err
	}
	if allowed == nil || sourceAllowed == nil {
		return nil, tags.ErrScopeMismatch
	}
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	ids := make([]string, 0, len(s.prefixes))
	for id := range s.prefixes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	used := int64(0)
	var result []tags.PrefixProjection
	for _, id := range ids {
		if !allowed[id] || !sourceAllowed[id] {
			continue
		}
		for _, item := range s.prefixes[id] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			used += 512 + int64(len(item.TenantID)+len(item.ContextID)+len(item.ID))
			if used > maxBytes {
				return nil, ErrTagSnapshotBudget
			}
			for key, value := range item.Values {
				used += 128 + int64(len(key)+len(value))
				if used > maxBytes {
					return nil, ErrTagSnapshotBudget
				}
			}
			item.Values = cloneFlowPrefixValues(item.Values)
			result = append(result, item)
		}
	}
	return result, nil
}

func cloneFlowPrefixValues(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
