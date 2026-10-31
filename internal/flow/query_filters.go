// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"strings"
)

// QueryFilterGroup is an include/exclude expression over conditions and child
// groups. All means AND; any means OR. Exclude negates the whole expression.
// Saved references must be resolved under tenant RLS and revalidated afterward.
type QueryFilterGroup struct {
	Match      string                `json:"match"`
	Mode       string                `json:"mode"`
	Conditions []QueryPredicate      `json:"conditions,omitempty"`
	Groups     []QueryFilterGroup    `json:"groups,omitempty"`
	Saved      []QuerySavedFilterRef `json:"saved,omitempty"`
}

// QuerySavedFilterRef identifies a tenant-owned reusable expression. The query
// cannot carry a tenant selector, table, SQL, or permission override in a ref.
type QuerySavedFilterRef struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}

// NormalizeQueryFilterGroup validates structure before traversal exceeds the
// depth/node/condition budget. Call again on the fully expanded saved filters.
func NormalizeQueryFilterGroup(input *QueryFilterGroup) (*QueryFilterGroup, error) {
	if input == nil {
		return nil, nil
	}
	conditions, nodes := 0, 0
	var visit func(QueryFilterGroup, int) (QueryFilterGroup, error)
	visit = func(group QueryFilterGroup, depth int) (QueryFilterGroup, error) {
		if depth > MaxQueryFilterDepth {
			return QueryFilterGroup{}, errors.New("flow filter nesting exceeds five levels")
		}
		nodes++
		if nodes > MaxQueryPredicates {
			return QueryFilterGroup{}, errors.New("flow filter group budget exceeded")
		}
		size := len(group.Conditions) + len(group.Groups) + len(group.Saved)
		if size == 0 || size > MaxQueryGroupEntries {
			return QueryFilterGroup{}, errors.New("flow filter groups require 1-250 conditions, child groups or saved references")
		}
		match := strings.ToLower(strings.TrimSpace(group.Match))
		switch match {
		case "", "all", "and":
			match = "all"
		case "any", "or":
			match = "any"
		default:
			return QueryFilterGroup{}, errors.New("flow group match must be all/AND or any/OR")
		}
		mode, err := normalizeFilterMode(group.Mode)
		if err != nil {
			return QueryFilterGroup{}, err
		}
		conditions += len(group.Conditions) + len(group.Saved)
		if conditions > MaxQueryPredicates {
			return QueryFilterGroup{}, errors.New("flow filters exceed 1000 expanded conditions")
		}
		predicates, err := NormalizeQueryPredicates(group.Conditions)
		if err != nil {
			return QueryFilterGroup{}, err
		}
		out := QueryFilterGroup{Match: match, Mode: mode, Conditions: predicates}
		for _, reference := range group.Saved {
			id := strings.TrimSpace(reference.ID)
			if id == "" || len(id) > 128 {
				return QueryFilterGroup{}, errors.New("invalid saved flow filter identifier")
			}
			refMode, err := normalizeFilterMode(reference.Mode)
			if err != nil {
				return QueryFilterGroup{}, err
			}
			out.Saved = append(out.Saved, QuerySavedFilterRef{ID: id, Mode: refMode})
		}
		for _, child := range group.Groups {
			normalized, err := visit(child, depth+1)
			if err != nil {
				return QueryFilterGroup{}, err
			}
			out.Groups = append(out.Groups, normalized)
		}
		return out, nil
	}
	result, err := visit(*input, 1)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func normalizeFilterMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "include":
		return "include", nil
	case "exclude":
		return "exclude", nil
	default:
		return "", errors.New("flow group mode must be include or exclude")
	}
}

// QueryFilterFields visits the complete normalized inline expression. Saved
// references must be expanded first so metadata permissions cannot be hidden.
func QueryFilterFields(group *QueryFilterGroup) []string {
	names := []string{}
	seen := map[string]bool{}
	var visit func(*QueryFilterGroup)
	visit = func(g *QueryFilterGroup) {
		if g == nil {
			return
		}
		for _, p := range g.Conditions {
			if !seen[p.Field] {
				names = append(names, p.Field)
				seen[p.Field] = true
			}
		}
		for i := range g.Groups {
			visit(&g.Groups[i])
		}
	}
	visit(group)
	return names
}
