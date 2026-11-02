// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"time"
)

// SavedQueryFilter is reusable tenant-owned configuration. Scope is retained
// internally to verify a storage response, but never taken from request JSON.
type SavedQueryFilter struct {
	ID          string           `json:"id"`
	TenantID    string           `json:"-"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Expression  QueryFilterGroup `json:"expression"`
	Version     int64            `json:"version"`
	VersionText string           `json:"version_text"`
	UpdatedBy   string           `json:"updated_by"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// QueryFilterReader applies tenant scope in its backing storage before lookup.
// Foreign/missing IDs are indistinguishable; callers cannot name a tenant in a
// saved reference. A raw unscoped configuration reader does not satisfy this API.
type QueryFilterReader interface {
	GetQueryFilter(context.Context, string, string) (SavedQueryFilter, error)
}

// ResolvedQueryFilters retains saved-filter versions separately from the
// expanded expression for the result identity and an auditable query receipt.
type ResolvedQueryFilters struct {
	Expression *QueryFilterGroup
	Versions   map[string]int64
}

// ResolveQueryFilters expands reusable expressions with tenant-first reads,
// cycle detection and budgets enforced during expansion, before a large tree
// can be allocated. updatingID seeds cycle detection for a saved-filter update.
func ResolveQueryFilters(ctx context.Context, tenant string, input *QueryFilterGroup, reader QueryFilterReader, updatingID string) (ResolvedQueryFilters, error) {
	return resolveQueryFilters(ctx, tenant, input, reader, updatingID, NormalizeQueryFilterGroup)
}

// ResolveQueryFiltersWithVocabulary expands saved references using the same
// tenant-bound field registry as the final plan. A saved tag predicate cannot
// bypass validation by hiding behind a native-only reference.
func ResolveQueryFiltersWithVocabulary(ctx context.Context, tenant string, input *QueryFilterGroup,
	reader QueryFilterReader, updatingID string, vocabulary QueryVocabulary) (ResolvedQueryFilters, error) {
	if vocabulary.tenantID != tenant {
		return ResolvedQueryFilters{}, errors.New("flow tag vocabulary does not match tenant scope")
	}
	return resolveQueryFilters(ctx, tenant, input, reader, updatingID, func(group *QueryFilterGroup) (*QueryFilterGroup, error) {
		return NormalizeQueryFilterGroupWithVocabulary(group, vocabulary)
	})
}

func resolveQueryFilters(ctx context.Context, tenant string, input *QueryFilterGroup,
	reader QueryFilterReader, updatingID string,
	normalize func(*QueryFilterGroup) (*QueryFilterGroup, error)) (ResolvedQueryFilters, error) {
	if tenant == "" {
		return ResolvedQueryFilters{}, errors.New("flow saved filters require authenticated tenant scope")
	}
	root, err := normalize(input)
	if err != nil {
		return ResolvedQueryFilters{}, err
	}
	result := ResolvedQueryFilters{Versions: map[string]int64{}}
	cache := map[string]SavedQueryFilter{}
	path := map[string]bool{}
	if updatingID != "" {
		path[updatingID] = true
	}
	conditions, nodes := 0, 0
	var expand func(*QueryFilterGroup, int) (*QueryFilterGroup, error)
	expand = func(group *QueryFilterGroup, depth int) (*QueryFilterGroup, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if group == nil {
			return nil, nil
		}
		if depth > MaxQueryFilterDepth {
			return nil, errors.New("expanded saved filters exceed five nesting levels")
		}
		nodes++
		conditions += len(group.Conditions)
		if nodes > MaxQueryPredicates || conditions > MaxQueryPredicates {
			return nil, errors.New("expanded saved filters exceed the query expression budget")
		}
		// Normalize again to own the condition slices and validate stored content.
		normalized, err := normalize(group)
		if err != nil {
			return nil, err
		}
		out := &QueryFilterGroup{Match: normalized.Match, Mode: normalized.Mode, Conditions: normalized.Conditions}
		for i := range normalized.Groups {
			child, err := expand(&normalized.Groups[i], depth+1)
			if err != nil {
				return nil, err
			}
			out.Groups = append(out.Groups, *child)
		}
		for _, reference := range normalized.Saved {
			if path[reference.ID] {
				return nil, errors.New("saved flow filter reference cycle")
			}
			if reader == nil {
				return nil, errors.New("saved flow filter store is unavailable")
			}
			saved, ok := cache[reference.ID]
			if !ok {
				saved, err = reader.GetQueryFilter(ctx, tenant, reference.ID)
				if err != nil {
					return nil, err
				}
				if saved.TenantID != tenant || saved.ID != reference.ID || saved.Version < 1 {
					return nil, errors.New("saved flow filter storage scope or version mismatch")
				}
				cache[reference.ID] = saved
			}
			path[reference.ID] = true
			child, err := expand(&saved.Expression, depth+1)
			delete(path, reference.ID)
			if err != nil {
				return nil, err
			}
			if reference.Mode == "exclude" {
				if child.Mode == "exclude" {
					child.Mode = "include"
				} else {
					child.Mode = "exclude"
				}
			}
			out.Groups = append(out.Groups, *child)
			result.Versions[reference.ID] = saved.Version
		}
		return out, nil
	}
	result.Expression, err = expand(root, 1)
	if err != nil {
		return ResolvedQueryFilters{}, err
	}
	result.Expression, err = normalize(result.Expression)
	if err != nil {
		return ResolvedQueryFilters{}, err
	}
	return result, nil
}
