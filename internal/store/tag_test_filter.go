// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *TestTagSnapshot) filterScope(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.valid(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenantID || tenantID != s.tenantID {
		return tags.ErrScopeMismatch
	}
	return nil
}

// BindFilter normalizes the existing nested predicate grammar over this test
// subject's root tags and captures immutable definition IDs. A saving caller
// must persist both outputs, then supply those IDs to SelectContext. This is
// not an authorization decision; the transport/job must authorize its caller.
func (s *TestTagSnapshot) BindFilter(ctx context.Context, tenantID string, input *flow.QueryFilterGroup, maxBytes int64) (*flow.QueryFilterGroup, map[string]string, error) {
	normalized, ids, _, err := s.prepareFilter(ctx, tenantID, input, maxBytes)
	return normalized, ids, err
}

func (s *TestTagSnapshot) prepareFilter(ctx context.Context, tenantID string, input *flow.QueryFilterGroup, maxBytes int64) (*flow.QueryFilterGroup, map[string]string, flow.QueryVocabulary, error) {
	if err := s.filterScope(ctx, tenantID); err != nil {
		return nil, nil, flow.QueryVocabulary{}, err
	}
	if input == nil {
		return nil, nil, flow.QueryVocabulary{}, tags.ErrInvalid
	}
	if err := testTagFilterInputBudget(ctx, input, s.definitions, maxBytes); err != nil {
		return nil, nil, flow.QueryVocabulary{}, err
	}
	vocabulary, err := flow.NewTagQueryVocabulary(tenantID, s.definitions)
	if err != nil {
		return nil, nil, flow.QueryVocabulary{}, err
	}
	normalized, err := flow.NormalizeQueryFilterGroupWithVocabulary(input, vocabulary)
	if err != nil {
		return nil, nil, flow.QueryVocabulary{}, fmt.Errorf("%w: test metadata filter: %v", tags.ErrInvalid, err)
	}
	root := make(map[string]string, len(s.definitions))
	for _, definition := range s.definitions {
		root["tag."+definition.Key] = definition.ID
	}
	for _, field := range flow.QueryFilterFields(normalized) {
		if root[field] == "" {
			return nil, nil, flow.QueryVocabulary{}, fmt.Errorf("%w: test metadata filters require current root tag fields", tags.ErrInvalid)
		}
	}
	encoded, err := json.Marshal(normalized)
	if err != nil || len(encoded) > flow.MaxPlanGrammarBytes {
		return nil, nil, flow.QueryVocabulary{}, ErrTagSnapshotBudget
	}
	ids, err := flow.QueryViewTagIDs(flow.QueryPlan{Filter: normalized}, vocabulary)
	if err != nil {
		return nil, nil, flow.QueryVocabulary{}, err
	}
	if len(ids) == 0 {
		return nil, nil, flow.QueryVocabulary{}, tags.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, flow.QueryVocabulary{}, err
	}
	return normalized, ids, vocabulary, nil
}

// SelectContext checks current ownership and explicit context disclosure before
// evaluating even an exclusion or not-equal predicate. Missing/foreign/denied
// identities cannot match an empty value. Returned IDs are copied, sorted and
// unique; any scope, saved-identity, cost or cancellation failure is atomic.
func (s *TestTagSnapshot) SelectContext(ctx context.Context, tenantID string, testIDs []string, allowed map[string]bool, input *flow.QueryFilterGroup, savedTagIDs map[string]string, maxBytes int64) ([]string, error) {
	if err := s.filterScope(ctx, tenantID); err != nil {
		return nil, err
	}
	if allowed == nil {
		return nil, tags.ErrScopeMismatch
	}
	if savedTagIDs == nil {
		return nil, flow.ErrQueryViewStaleTag
	}
	// Preparation and selection coexist. Reserve disjoint portions of this
	// operation's memory budget rather than admitting each against the whole.
	normalized, current, vocabulary, err := s.prepareFilter(ctx, tenantID, input, maxBytes/2)
	if err != nil {
		return nil, err
	}
	if len(current) != len(savedTagIDs) {
		return nil, flow.ErrQueryViewStaleTag
	}
	for field, id := range current {
		if savedTagIDs[field] != id {
			return nil, flow.ErrQueryViewStaleTag
		}
	}
	prepared, err := flow.PrepareQueryFilterWithVocabulary(normalized, vocabulary)
	if err != nil {
		return nil, err
	}
	selected := []string{}
	seen := map[string]bool{}
	maxBytes /= 2
	used := int64(2048)
	for _, id := range testIDs {
		amount := int64(len(id)) + 512
		if amount > maxBytes-used {
			return nil, ErrTagSnapshotBudget
		}
		used += amount
		subject, err := s.ResolveContext(ctx, tenantID, id, allowed, maxBytes-used)
		if err != nil {
			return nil, err
		}
		if subject == nil || seen[subject.ID] {
			continue
		}
		seen[subject.ID] = true
		values := make(map[string]string, len(subject.Items))
		for _, item := range subject.Items {
			values[item.TagID] = item.Value
		}
		if prepared.Matches(func(field string) string { return values[current[field]] }) {
			selected = append(selected, subject.ID)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Strings(selected)
	return selected, nil
}

// Account before normalization/JSON/regex allocations. These are operation
// memory costs, not lower value/row reach limits. Keep the existing grammar
// limits and whole encoded envelope check in addition to this admission.
func testTagFilterInputBudget(ctx context.Context, input *flow.QueryFilterGroup, definitions []tags.Definition, maxBytes int64) error {
	used, nodes, conditions := int64(1024), 0, 0
	charge := func(bytes int) error {
		if maxBytes <= used || int64(bytes) > (maxBytes-used)/8 {
			return ErrTagSnapshotBudget
		}
		used += int64(bytes) * 8
		return nil
	}
	var visit func(*flow.QueryFilterGroup, int) error
	visit = func(group *flow.QueryFilterGroup, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		nodes++
		conditions += len(group.Conditions)
		if depth > flow.MaxQueryFilterDepth || nodes > flow.MaxQueryPredicates || conditions > flow.MaxQueryPredicates || len(group.Conditions)+len(group.Groups)+len(group.Saved) > flow.MaxQueryGroupEntries || len(group.Saved) != 0 {
			return tags.ErrInvalid
		}
		if err := charge(128 + len(group.Match) + len(group.Mode)); err != nil {
			return err
		}
		for _, predicate := range group.Conditions {
			if len(predicate.Values) > flow.MaxQueryValues {
				return tags.ErrInvalid
			}
			if err := charge(128 + len(predicate.Field) + len(predicate.Op)); err != nil {
				return err
			}
			for _, value := range predicate.Values {
				if err := charge(32 + len(value)); err != nil {
					return err
				}
			}
		}
		for i := range group.Groups {
			if err := visit(&group.Groups[i], depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	// The existing vocabulary materializes the tag fields and operator lists;
	// reserve that request-local allocation before building it. Subject
	// resolution itself was charged when the owning snapshot was loaded.
	for _, definition := range definitions {
		if err := charge(512 + len(definition.ID) + len(definition.Key)); err != nil {
			return err
		}
	}
	return visit(input, 1)
}
